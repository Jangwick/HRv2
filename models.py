from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import URLSafeTimedSerializer
from flask import current_app as app
from datetime import datetime, timedelta

db = SQLAlchemy()
ph = PasswordHasher()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='employee')  # 'employee', 'hr', 'admin'
    
    @property
    def has_complete_profile(self):
        """Check if user has completed their profile"""
        return hasattr(self, 'profile') and self.profile is not None and \
               self.profile.first_name is not None and \
               self.profile.last_name is not None
    
    def get_display_name(self):
        """Return user's full name if profile is complete, otherwise username"""
        if self.has_complete_profile:
            return self.profile.get_full_name()
        return self.username
    
    def set_password(self, password):
        self.password_hash = ph.hash(password)
        
    def verify_password(self, password):
        try:
            ph.verify(self.password_hash, password)
            return True
        except VerifyMismatchError:
            return False
            
    def is_admin(self):
        return self.role == 'admin'
        
    def is_hr(self):
        return self.role == 'hr'
        
    @classmethod
    def authenticate(cls, username_or_email, password):
        """Authenticate a user by either username or email and password."""
        # Try email first
        user = cls.query.filter_by(email=username_or_email).first()
        
        # If not found by email, try username
        if user is None:
            user = cls.query.filter_by(username=username_or_email).first()
        
        # Return user if found and password matches
        if user and user.verify_password(password):
            return user
        
        return None
    
    def get_reset_token(self, expires_sec=1800):
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return serializer.dumps(self.id, salt='reset-password')

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            user_id = serializer.loads(token, salt='reset-password', max_age=expires_sec)
        except:
            return None
        return User.query.get(user_id)
        
    def __repr__(self):
        return f'<User {self.username}>'

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)  # IPv6 can be up to 45 chars
    username_or_email = db.Column(db.String(120), nullable=True)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(255), nullable=True)
    
    @classmethod
    def is_rate_limited(cls, ip_address, window_minutes=15, max_attempts=5):
        """
        Check if the IP address is rate limited
        
        Args:
            ip_address: The IP address to check
            window_minutes: Time window in minutes to consider (default: 15)
            max_attempts: Maximum number of failed attempts allowed in the window (default: 5)
            
        Returns:
            tuple: (is_limited, message, remaining_attempts)
        """
        # Calculate the timestamp for the window
        window_start = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        # Count failed attempts in the window
        failed_attempts = cls.query.filter(
            cls.ip_address == ip_address,
            cls.success == False,
            cls.timestamp >= window_start
        ).count()
        
        if failed_attempts >= max_attempts:
            # Find the most recent attempt to calculate unlock time
            latest_attempt = cls.query.filter(
                cls.ip_address == ip_address,
                cls.success == False
            ).order_by(cls.timestamp.desc()).first()
            
            if latest_attempt:
                unlock_time = latest_attempt.timestamp + timedelta(minutes=window_minutes)
                now = datetime.utcnow()
                
                if now < unlock_time:
                    time_remaining = unlock_time - now
                    minutes = time_remaining.seconds // 60
                    seconds = time_remaining.seconds % 60
                    message = f"Too many failed login attempts. Please try again in {minutes}m {seconds}s."
                    return True, message, 0
        
        # IP is not rate limited
        remaining = max_attempts - failed_attempts
        return False, None, remaining
    
    @classmethod
    def log_attempt(cls, ip_address, username_or_email=None, success=False, user_agent=None):
        """Log a login attempt in the database"""
        attempt = cls(
            ip_address=ip_address,
            username_or_email=username_or_email,
            success=success,
            user_agent=user_agent
        )
        db.session.add(attempt)
        db.session.commit()
        
    @classmethod
    def reset_for_ip(cls, ip_address):
        """Reset failed attempts for an IP after successful login"""
        # This could either delete the attempts or mark them as handled
        # Here we'll leave the record for auditing but add successful login
        cls.log_attempt(ip_address, success=True)

class EmployeeProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone_number = db.Column(db.String(20))
    address = db.Column(db.String(200))
    city = db.Column(db.String(50))
    country = db.Column(db.String(50))
    bio = db.Column(db.Text)
    position = db.Column(db.String(100))
    hire_date = db.Column(db.Date)
    birth_date = db.Column(db.Date)
    
    # Updated fields for better Cloudinary management
    cloudinary_folder = db.Column(db.String(50), default='hr_profile_pictures')  # Store folder name
    cloudinary_public_id = db.Column(db.String(255), default='default-profile')  # Store actual public_id without folder
    cloudinary_version = db.Column(db.String(20))  # Store version for cache busting
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('profile', lazy=True, uselist=False))
    
    def get_full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return None
    
    def set_profile_image(self, cloudinary_result):
        """Update profile image with Cloudinary upload result data"""
        if cloudinary_result and 'public_id' in cloudinary_result:
            # Parse the public_id to extract folder and actual ID
            full_public_id = cloudinary_result['public_id']
            
            if '/' in full_public_id:
                parts = full_public_id.split('/')
                self.cloudinary_folder = parts[0]
                self.cloudinary_public_id = '/'.join(parts[1:])  # In case there are multiple slashes
            else:
                self.cloudinary_folder = 'hr_profile_pictures'  # Default folder
                self.cloudinary_public_id = full_public_id
            
            # Store the version for cache busting
            self.cloudinary_version = str(cloudinary_result.get('version', ''))
            return True
        return False
    
    def has_profile_image(self):
        """Check if user has a custom profile image"""
        return self.cloudinary_public_id and self.cloudinary_public_id != 'default-profile'
    
    @property
    def profile_image(self):
        """Compatibility property for existing code"""
        if not self.has_profile_image():
            return 'default-profile'
        return self.cloudinary_public_id
    
    @profile_image.setter
    def profile_image(self, value):
        """Setter for profile_image property - handles form population"""
        # This is just a compatibility setter
        # The actual image setting is handled via set_profile_image() with the Cloudinary result
        # We don't actually set anything here since this is called from form.populate_obj()
        pass
    
    @property
    def full_cloudinary_id(self):
        """Get the full Cloudinary public_id including folder"""
        if not self.has_profile_image():
            return None
        return f"{self.cloudinary_folder}/{self.cloudinary_public_id}"
    
    def get_cloudinary_url(self, width=300, height=300, crop='fill', format='auto', quality='auto'):
        """Generate a Cloudinary URL with the specified parameters"""
        if not self.has_profile_image():
            return None
        
        # This would ideally use cloudinary.utils.cloudinary_url but returns a formatted string
        # for simplicity in case the Cloudinary SDK is not available in templates
        base_url = f"https://res.cloudinary.com/demeqfksa/image/upload"
        transform = f"c_{crop},f_{format},h_{height},q_{quality},w_{width}"
        version = f"v{self.cloudinary_version}" if self.cloudinary_version else ""
        public_id = f"{self.cloudinary_folder}/{self.cloudinary_public_id}"
        
        # Build the URL with proper path segments
        if version:
            return f"{base_url}/{transform}/{version}/{public_id}"
        else:
            return f"{base_url}/{transform}/{public_id}"

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    leave_type = db.Column(db.String(50), nullable=False)  # vacation, sick, personal, etc.
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, denied
    reason = db.Column(db.Text)
    approval_comment = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    employee = db.relationship('User', foreign_keys=[employee_id], backref=db.backref('leave_requests', lazy='dynamic'))
    approver = db.relationship('User', foreign_keys=[approver_id], backref=db.backref('approved_leaves', lazy='dynamic'))
    
    @property
    def duration_days(self):
        """Calculate the duration of leave in days"""
        if self.start_date and self.end_date:
            # +1 to include both start and end dates
            return (self.end_date - self.start_date).days + 1
        return 0
    
    @property
    def is_pending(self):
        return self.status == 'pending'
    
    @property
    def is_approved(self):
        return self.status == 'approved'
    
    @property
    def is_denied(self):
        return self.status == 'denied'
    
    @property
    def status_badge_color(self):
        """Return Bootstrap color class based on status"""
        if self.status == 'approved':
            return 'bg-success'
        elif self.status == 'denied':
            return 'bg-danger'
        else:  # pending
            return 'bg-warning'

class TrainingProgram(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    instructor = db.Column(db.String(100))
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(100))
    max_participants = db.Column(db.Integer, default=0)  # 0 means unlimited
    category = db.Column(db.String(50), nullable=False)  # technical, soft-skills, compliance, etc.
    status = db.Column(db.String(20), default='upcoming')  # upcoming, in-progress, completed, cancelled
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    creator = db.relationship('User', foreign_keys=[created_by], backref=db.backref('created_trainings', lazy='dynamic'))
    enrollments = db.relationship('TrainingEnrollment', back_populates='training', cascade='all, delete-orphan')
    
    @property
    def duration_days(self):
        """Calculate the duration in days"""
        if self.start_date and self.end_date:
            return (self.end_date - self.start_date).days + 1
        return 0
    
    @property
    def enrolled_count(self):
        """Get the number of enrolled participants"""
        return TrainingEnrollment.query.filter_by(training_id=self.id).count()
    
    @property
    def is_full(self):
        """Check if the training has reached max participants"""
        if self.max_participants == 0:  # Unlimited participants
            return False
        return self.enrolled_count >= self.max_participants
    
    @property
    def status_badge_color(self):
        """Return Bootstrap color class based on status"""
        if self.status == 'upcoming':
            return 'bg-primary'
        elif self.status == 'in-progress':
            return 'bg-warning'
        elif self.status == 'completed':
            return 'bg-success'
        else:  # cancelled
            return 'bg-danger'
    
    @property
    def is_upcoming(self):
        today = datetime.now().date()
        return self.start_date > today
    
    @property
    def is_in_progress(self):
        today = datetime.now().date()
        return self.start_date <= today <= self.end_date
    
    @property
    def is_completed(self):
        today = datetime.now().date()
        return self.end_date < today
    
    def update_status(self):
        """Update status based on dates"""
        today = datetime.now().date()
        
        if self.status == 'cancelled':
            return  # Don't change status if it's cancelled
            
        if self.start_date > today:
            self.status = 'upcoming'
        elif self.start_date <= today <= self.end_date:
            self.status = 'in-progress'
        elif self.end_date < today:
            self.status = 'completed'

class TrainingEnrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    training_id = db.Column(db.Integer, db.ForeignKey('training_program.id'), nullable=False)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='enrolled')  # enrolled, completed, dropped, failed
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)
    completion_date = db.Column(db.DateTime)
    feedback = db.Column(db.Text)
    rating = db.Column(db.Integer)  # 1-5 stars
    
    # Define unique constraint to prevent duplicate enrollments
    __table_args__ = (
        db.UniqueConstraint('training_id', 'employee_id', name='unique_enrollment'),
    )
    
    training = db.relationship('TrainingProgram', back_populates='enrollments')
    employee = db.relationship('User', backref=db.backref('training_enrollments', lazy='dynamic'))
    
    @property
    def status_badge_color(self):
        """Return Bootstrap color class based on status"""
        if self.status == 'enrolled':
            return 'bg-primary'
        elif self.status == 'completed':
            return 'bg-success'
        elif self.status == 'dropped':
            return 'bg-warning'
        else:  # failed
            return 'bg-danger'

class EmployeeSalary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), default='USD', nullable=False)
    effective_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=True)  # Null if it's the current salary
    salary_type = db.Column(db.String(20), default='monthly', nullable=False)  # monthly, annual, hourly
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    employee = db.relationship('User', foreign_keys=[employee_id], backref=db.backref('salaries', lazy='dynamic'))
    creator = db.relationship('User', foreign_keys=[created_by])
    
    @property
    def is_active(self):
        """Check if this is the current active salary"""
        return self.end_date is None or self.end_date >= datetime.now().date()
    
    @property
    def formatted_amount(self):
        """Format the amount with currency"""
        return f"{self.currency} {self.amount:,.2f}"
    
    @property
    def annualized_amount(self):
        """Calculate the annual equivalent of the salary"""
        if self.salary_type == 'hourly':
            # Assuming 40 hour work week, 52 weeks per year
            return self.amount * 40 * 52
        elif self.salary_type == 'monthly':
            return self.amount * 12
        else:  # annual
            return self.amount
