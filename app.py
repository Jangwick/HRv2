import os
from flask import Flask, render_template, redirect, url_for, flash, request, abort, session, Response, send_file, send_from_directory, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, LoginAttempt, EmployeeProfile, LeaveRequest, TrainingProgram, TrainingEnrollment, EmployeeSalary
from forms import (LoginForm, SignupForm, RequestResetForm, ResetPasswordForm, 
                  ProfileForm, EmployeeSearchForm, LeaveRequestForm, LeaveApprovalForm,
                  TrainingProgramForm, EnrollmentForm, TrainingFeedbackForm,
                  SalaryForm, SalaryReportForm)
from argon2 import PasswordHasher
from functools import wraps
import sqlite3
from flask_mail import Mail, Message
import time
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os.path
from dotenv import load_dotenv
from cloud_config import upload_profile_image, get_optimized_url, delete_profile_image
import csv, io
import pandas as pd
# Replace WeasyPrint with ReportLab for PDF generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import tempfile

# Import the chatbot
from chatbot import chatbot

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)
# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'welptest12@gmail.com'  # Replace with your Gmail
app.config['MAIL_PASSWORD'] = 'ylwz hhwq bvjz gpgb'     # Use App Password, not regular password
app.config['MAIL_DEFAULT_SENDER'] = ('HR System', 'no-reply@gmail.com')
# Configure upload folder
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit uploads to 16MB

# Initialize extensions
mail = Mail(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize database
db.init_app(app)

# Initialize Argon2 password hasher
ph = PasswordHasher()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Custom decorators for role-based access
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash("You don't have permission to access this page", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def hr_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (not current_user.is_hr() and not current_user.is_admin()):
            flash("You don't have permission to access this page", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

# Replace the existing save_profile_image function with this updated one
def save_profile_image(form_picture, user_id, old_image=None):
    """Save profile picture to Cloudinary and return the upload result"""
    if not form_picture:
        return None

    # Generate a unique ID for the image
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    public_id = f"user_{user_id}_{timestamp}"

    # Delete old image if it exists and is not the default
    if old_image and old_image != 'default-profile':
        # This is where the deletion occurs - let's make sure it works properly
        success = delete_profile_image(old_image)
        if not success:
            app.logger.warning(f"Failed to delete old profile image: {old_image}")

    # Upload to Cloudinary
    return upload_profile_image(form_picture, public_id)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Get the client's IP address
    ip_address = request.remote_addr
    user_agent = request.user_agent.string
    
    # Check rate limiting from database
    is_limited, limit_message, attempts_left = LoginAttempt.is_rate_limited(ip_address)
    
    if is_limited:
        flash(limit_message, 'danger')
        return render_template('login.html', form=LoginForm(), rate_limited=True, 
                               attempts=5-attempts_left)
    
    form = LoginForm()
    if form.validate_on_submit():
        username_or_email = form.username_or_email.data
        user = User.authenticate(username_or_email, form.password.data)
        
        if user:
            # Successful login - reset login attempts
            LoginAttempt.log_attempt(ip_address, username_or_email, success=True, user_agent=user_agent)
            LoginAttempt.reset_for_ip(ip_address)
            
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            
            # Log the successful login
            app.logger.info(f"Successful login for user {user.username} from IP {ip_address}")
            
            return redirect(next_page or url_for('dashboard'))
        else:
            # Failed login - record the attempt
            LoginAttempt.log_attempt(ip_address, username_or_email, success=False, user_agent=user_agent)
            
            # Get updated count for display
            is_limited, limit_message, attempts_left = LoginAttempt.is_rate_limited(ip_address)
            
            if attempts_left <= 0:
                flash('Too many failed login attempts. Your account has been temporarily locked.', 'danger')
            else:
                flash(f'Invalid username/email or password. You have {attempts_left} attempts remaining.', 'danger')
            
            # Log the failed attempt
            app.logger.warning(f"Failed login attempt for {username_or_email} from IP {ip_address}")
                
    return render_template('login.html', form=form, attempts=5-attempts_left if 'attempts_left' in locals() else 0)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Check if admin exists to modify form choices
    admin_exists = User.query.filter_by(role='admin').first() is not None
    
    form = SignupForm()
    # Modify role choices if admin already exists
    if admin_exists:
        form.role.choices = [
            ('employee', 'Employee'),
            ('hr', 'HR')
        ]
    
    if form.validate_on_submit():
        # Check if user already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered', 'danger')
            return render_template('signup.html', form=form, admin_exists=admin_exists)
        
        # Check if username already exists
        existing_username = User.query.filter_by(username=form.username.data).first()
        if existing_username:
            flash('Username already taken', 'danger')
            return render_template('signup.html', form=form, admin_exists=admin_exists)
        
        # Check if the first user is being created
        is_first_user = User.query.count() == 0
        
        # Determine appropriate role
        role = form.role.data
        
        # If not the first user and trying to register as admin without being an admin
        if not is_first_user and role == 'admin' and not current_user.is_authenticated:
            flash('Admin role requires authorization. Your account has been created with Employee role.', 'warning')
            role = 'employee'
        elif not is_first_user and role == 'hr' and not current_user.is_authenticated:
            flash('HR role requires authorization. Your account has been created with Employee role.', 'warning')
            role = 'employee'
        
        # Create new user
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            department=form.department.data,
            role=role  # Use the determined role
        )
        new_user.set_password(form.password.data)
        
        # Save user to database
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('signup.html', form=form, admin_exists=admin_exists)

@app.route('/dashboard')
@login_required
def dashboard():
    # Get the current user's profile
    profile = EmployeeProfile.query.filter_by(user_id=current_user.id).first()
    
    # If no profile exists yet, create a default one
    if not profile:
        profile = EmployeeProfile(user_id=current_user.id)
        db.session.add(profile)
        db.session.commit()
    
    # Pass the profile to the template
    return render_template('dashboard.html', profile=profile)

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/hr/dashboard')
@login_required
@hr_required
def hr_dashboard():
    users = User.query.filter_by(role='employee').all()
    return render_template('hr_dashboard.html', users=users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Add an admin route to view login attempts
@app.route('/admin/login-attempts')
@login_required
@admin_required
def admin_login_attempts():
    # Get all login attempts, ordered by most recent first
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(100).all()
    return render_template('admin_login_attempts.html', attempts=attempts)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page and editing"""
    # Get or create user profile
    user_profile = EmployeeProfile.query.filter_by(user_id=current_user.id).first()
    if not user_profile:
        user_profile = EmployeeProfile(user_id=current_user.id)
        db.session.add(user_profile)
        db.session.commit()
        
    form = ProfileForm(obj=user_profile)
    if form.validate_on_submit():
        # Store form fields except profile_image in a dict
        # This avoids the AttributeError with the profile_image property
        form_data = {field.name: field.data for field in form if field.name != 'profile_image' and field.name != 'submit'}
        
        # Update user profile fields manually
        for field, value in form_data.items():
            setattr(user_profile, field, value)
        
        # Handle profile image if provided
        if form.profile_image.data:
            # Save the old image public_id for deletion after successful upload
            old_image = user_profile.cloudinary_public_id if user_profile.has_profile_image() else None
            
            # Upload to Cloudinary
            result = save_profile_image(form.profile_image.data, current_user.id, old_image)
            
            # Update the profile with Cloudinary data
            if result:
                user_profile.set_profile_image(result)
                app.logger.info(f"Profile image updated for user {current_user.id}, old image: {old_image}")
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
        
    return render_template('profile.html', form=form, user=current_user, profile=user_profile)

@app.route('/employees')
@login_required
@hr_required
def employee_list():
    """Display list of employees (HR and Admin only)"""
    form = EmployeeSearchForm(request.args, meta={'csrf': False})
    
    # Base query
    query = User.query.join(User.profile, isouter=True)
    
    # Apply filters if provided
    if form.validate():
        # Filter by search term in name or email
        if form.search.data:
            search_term = f"%{form.search.data}%"
            query = query.filter(
                db.or_(
                    User.username.like(search_term),
                    User.email.like(search_term),
                    EmployeeProfile.first_name.like(search_term),
                    EmployeeProfile.last_name.like(search_term)
                )
            )
        
        # Filter by department
        if form.department.data:
            query = query.filter(User.department == form.department.data)
    
    # Get employees (exclude admins if current user is HR but not admin)
    if current_user.is_admin():
        employees = query.order_by(User.username).all()
    else:
        employees = query.filter(User.role != 'admin').order_by(User.username).all()
    
    return render_template('employee_list.html', employees=employees, form=form)

@app.route('/employees/<int:employee_id>')
@login_required
@hr_required
def employee_detail(employee_id):
    """Display employee details (HR and Admin only)"""
    user = User.query.get_or_404(employee_id)
    
    # Don't allow HR staff to view admin profiles unless they are admin
    if user.role == 'admin' and not current_user.is_admin():
        flash("You don't have permission to view this profile", "danger")
        return redirect(url_for('employee_list'))
        
    return render_template('employee_detail.html', employee=user)

# Add a helper context processor to make Cloudinary URL generation available in templates
@app.context_processor
def utility_processor():
    def get_profile_image_url(profile_image, width=300, height=300, version=None):
        # Handle the default case
        if not profile_image or profile_image == 'default-profile':
            return url_for('static', filename='img/default-profile.png')
        
        # Get optimized URL with version for cache busting if available
        return get_optimized_url(profile_image, width, height, version=version)
        
    # Add current date to context for templates
    now = datetime.now()
    
    return dict(get_profile_image_url=get_profile_image_url, now=now)

# Leave Request Routes
@app.route('/leaves')
@login_required
def leaves():
    """View leave requests - employees see their own, HR/admin see all"""
    if current_user.is_admin() or current_user.is_hr():
        # HR and admins see all pending requests
        pending_requests = LeaveRequest.query.filter_by(status='pending').order_by(LeaveRequest.start_date).all()
        # Also see recent approved/denied requests
        processed_requests = LeaveRequest.query.filter(
            LeaveRequest.status.in_(['approved', 'denied'])
        ).order_by(LeaveRequest.updated_at.desc()).limit(10).all()
    else:
        # Regular employees only see their own requests
        pending_requests = LeaveRequest.query.filter_by(
            employee_id=current_user.id, status='pending'
        ).order_by(LeaveRequest.start_date).all()
        processed_requests = LeaveRequest.query.filter(
            LeaveRequest.employee_id==current_user.id,
            LeaveRequest.status.in_(['approved', 'denied'])
        ).order_by(LeaveRequest.updated_at.desc()).all()
        
    return render_template('leaves/index.html', 
                          pending_requests=pending_requests, 
                          processed_requests=processed_requests)

@app.route('/leaves/new', methods=['GET', 'POST'])
@login_required
def new_leave():
    """Create a new leave request"""
    form = LeaveRequestForm()
    if form.validate_on_submit():
        leave_request = LeaveRequest(
            employee_id=current_user.id,
            leave_type=form.leave_type.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            reason=form.reason.data,
            status='pending'
        )
        db.session.add(leave_request)
        db.session.commit()
        flash('Your leave request has been submitted successfully!', 'success')
        return redirect(url_for('leaves'))
        
    return render_template('leaves/new.html', form=form)

@app.route('/leaves/<int:leave_id>')
@login_required
def view_leave(leave_id):
    """View details of a specific leave request"""
    leave = LeaveRequest.query.get_or_404(leave_id)
    
    # Check if user has permission to view this leave request
    if not (current_user.id == leave.employee_id or current_user.is_hr() or current_user.is_admin()):
        flash("You don't have permission to view this leave request", "danger")
        return redirect(url_for('dashboard'))
        
    return render_template('leaves/view.html', leave=leave)

@app.route('/leaves/<int:leave_id>/process', methods=['GET', 'POST'])
@login_required
@hr_required
def process_leave(leave_id):
    """Process (approve/deny) a leave request"""
    leave = LeaveRequest.query.get_or_404(leave_id)
    
    # Ensure the request is still pending
    if leave.status != 'pending':
        flash('This leave request has already been processed', 'warning')
        return redirect(url_for('view_leave', leave_id=leave.id))
    
    form = LeaveApprovalForm()
    if form.validate_on_submit():
        leave.status = form.status.data
        leave.approval_comment = form.comment.data
        leave.approver_id = current_user.id
        leave.updated_at = datetime.utcnow()
        db.session.commit()
        
        status_text = 'approved' if leave.status == 'approved' else 'denied'
        flash(f'The leave request has been {status_text}', 'success')
        return redirect(url_for('leaves'))
        
    return render_template('leaves/process.html', form=form, leave=leave)

# Training Programs Routes
@app.route('/trainings')
@login_required
def trainings():
    """View all training programs"""
    # Get upcoming and in-progress trainings
    active_trainings = TrainingProgram.query.filter(
        TrainingProgram.status.in_(['upcoming', 'in-progress'])
    ).order_by(TrainingProgram.start_date).all()
    
    # Get completed trainings
    completed_trainings = TrainingProgram.query.filter_by(
        status='completed'
    ).order_by(TrainingProgram.end_date.desc()).limit(5).all()
    
    # Check if the user is already enrolled in each training
    user_enrollments = {
        e.training_id: e for e in TrainingEnrollment.query.filter_by(employee_id=current_user.id).all()
    }
    
    return render_template('trainings/index.html', 
                          active_trainings=active_trainings,
                          completed_trainings=completed_trainings,
                          user_enrollments=user_enrollments)

@app.route('/trainings/new', methods=['GET', 'POST'])
@login_required
@hr_required
def new_training():
    """Create a new training program"""
    form = TrainingProgramForm()
    if form.validate_on_submit():
        training = TrainingProgram(
            title=form.title.data,
            description=form.description.data,
            instructor=form.instructor.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            location=form.location.data,
            max_participants=form.max_participants.data,
            category=form.category.data,
            status=form.status.data,
            created_by=current_user.id
        )
        db.session.add(training)
        db.session.commit()
        flash('Training program created successfully!', 'success')
        return redirect(url_for('trainings'))
        
    return render_template('trainings/new.html', form=form)

@app.route('/trainings/<int:training_id>')
@login_required
def view_training(training_id):
    """View a specific training program"""
    training = TrainingProgram.query.get_or_404(training_id)
    
    # Check if the current user is enrolled
    enrollment = TrainingEnrollment.query.filter_by(
        training_id=training_id, employee_id=current_user.id
    ).first()
    
    # Get list of enrolled employees for HR/admin
    enrolled_employees = []
    if current_user.is_hr() or current_user.is_admin():
        enrolled_employees = db.session.query(User, TrainingEnrollment)\
            .join(TrainingEnrollment, User.id == TrainingEnrollment.employee_id)\
            .filter(TrainingEnrollment.training_id == training_id)\
            .all()
    
    return render_template('trainings/view.html', 
                          training=training, 
                          enrollment=enrollment,
                          enrolled_employees=enrolled_employees)

@app.route('/trainings/<int:training_id>/edit', methods=['GET', 'POST'])
@login_required
@hr_required
def edit_training(training_id):
    """Edit a training program"""
    training = TrainingProgram.query.get_or_404(training_id)
    form = TrainingProgramForm(obj=training)
    if form.validate_on_submit():
        form.populate_obj(training)
        db.session.commit()
        flash('Training program updated successfully!', 'success')
        return redirect(url_for('view_training', training_id=training.id))
        
    return render_template('trainings/edit.html', form=form, training=training)

@app.route('/trainings/<int:training_id>/enroll', methods=['GET', 'POST'])
@login_required
def enroll_training(training_id):
    """Enroll in a training program"""
    training = TrainingProgram.query.get_or_404(training_id)
    
    # Check if enrollment is still possible
    if training.status not in ['upcoming', 'in-progress']:
        flash('Enrollment is not available for this training.', 'warning')
        return redirect(url_for('view_training', training_id=training_id))
    
    # Check if training is full
    if training.is_full:
        flash('This training is at maximum capacity.', 'warning')
        return redirect(url_for('view_training', training_id=training_id))
    
    # HR or Admin can enroll multiple employees
    if current_user.is_hr() or current_user.is_admin():
        form = EnrollmentForm()
        
        # Get employees who aren't already enrolled
        enrolled_ids = [e.employee_id for e in TrainingEnrollment.query.filter_by(training_id=training_id).all()]
        available_employees = User.query.filter(User.id.notin_(enrolled_ids) if enrolled_ids else True).all()
        
        form.employees.choices = [(e.id, e.get_display_name() or e.username) for e in available_employees]
        
        if form.validate_on_submit():
            for employee_id in form.employees.data:
                enrollment = TrainingEnrollment(
                    training_id=training_id,
                    employee_id=employee_id
                )
                db.session.add(enrollment)
            
            db.session.commit()
            flash(f'Successfully enrolled {len(form.employees.data)} employees!', 'success')
            return redirect(url_for('view_training', training_id=training_id))
            
        return render_template('trainings/enroll.html', form=form, training=training)
    else:
        # Regular employees can only enroll themselves
        # Check if already enrolled
        existing_enrollment = TrainingEnrollment.query.filter_by(
            training_id=training_id, employee_id=current_user.id
        ).first()
        
        if existing_enrollment:
            flash('You are already enrolled in this training.', 'info')
            return redirect(url_for('view_training', training_id=training_id))
            
        # Create new enrollment
        enrollment = TrainingEnrollment(
            training_id=training_id,
            employee_id=current_user.id
        )
        db.session.add(enrollment)
        db.session.commit()
        
        flash('You have successfully enrolled in this training!', 'success')
        return redirect(url_for('view_training', training_id=training_id))

@app.route('/trainings/<int:training_id>/unenroll/<int:employee_id>', methods=['POST'])
@login_required
def unenroll_training(training_id, employee_id):
    """Unenroll from a training program"""
    # Check if user has permission (self or HR/admin)
    if employee_id != current_user.id and not (current_user.is_hr() or current_user.is_admin()):
        flash("You don't have permission to unenroll other employees.", "danger")
        return redirect(url_for('view_training', training_id=training_id))
    
    enrollment = TrainingEnrollment.query.filter_by(
        training_id=training_id, employee_id=employee_id
    ).first_or_404()
    
    db.session.delete(enrollment)
    db.session.commit()
    
    if employee_id == current_user.id:
        flash('You have been unenrolled from this training.', 'success')
    else:
        employee = User.query.get(employee_id)
        flash(f'{employee.username} has been unenrolled from this training.', 'success')
        
    return redirect(url_for('view_training', training_id=training_id))

@app.route('/trainings/my-enrollments')
@login_required
def my_enrollments():
    """View my training enrollments"""
    # Get active enrollments (upcoming and in-progress)
    active_enrollments = db.session.query(TrainingEnrollment)\
        .join(TrainingProgram, TrainingEnrollment.training_id == TrainingProgram.id)\
        .filter(TrainingEnrollment.employee_id == current_user.id,
                TrainingProgram.status.in_(['upcoming', 'in-progress']))\
        .order_by(TrainingProgram.start_date).all()
    
    # Get completed enrollments
    completed_enrollments = db.session.query(TrainingEnrollment)\
        .join(TrainingProgram, TrainingEnrollment.training_id == TrainingProgram.id)\
        .filter(TrainingEnrollment.employee_id == current_user.id,
                TrainingProgram.status == 'completed')\
        .order_by(TrainingProgram.end_date.desc()).all()
        
    return render_template('trainings/my_enrollments.html',
                          active_enrollments=active_enrollments,
                          completed_enrollments=completed_enrollments)

@app.route('/trainings/<int:training_id>/feedback', methods=['GET', 'POST'])
@login_required
def training_feedback(training_id):
    """Submit feedback for a completed training"""
    training = TrainingProgram.query.get_or_404(training_id)
    
    # Check if the user is enrolled
    enrollment = TrainingEnrollment.query.filter_by(
        training_id=training_id, employee_id=current_user.id
    ).first_or_404()
    
    # Check if training is completed
    if training.status != 'completed':
        flash('Feedback can only be submitted for completed trainings.', 'warning')
        return redirect(url_for('view_training', training_id=training_id))
        
    # Check if feedback already submitted
    if enrollment.status == 'completed':
        flash('You have already submitted feedback for this training.', 'info')
        return redirect(url_for('view_training', training_id=training_id))
    
    form = TrainingFeedbackForm()
    
    if form.validate_on_submit():
        enrollment.rating = form.rating.data
        enrollment.feedback = form.feedback.data
        enrollment.status = 'completed'
        enrollment.feedback_date = datetime.utcnow()
        
        db.session.commit()
        
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('view_training', training_id=training_id))
        
    return render_template('trainings/feedback.html', form=form, training=training)

@app.route('/hr/reports')
@login_required
@hr_required
def hr_reports():
    """Display HR reports dashboard"""
    return render_template('reports/index.html')

@app.route('/hr/reports/salary', methods=['GET', 'POST'])
@login_required
@hr_required
def salary_report():
    """Generate salary reports"""
    form = SalaryReportForm()
    
    if form.validate_on_submit() or request.args.get('export_format'):
        # For GET requests with export_format, use default parameters
        if request.method == 'GET' and request.args.get('export_format'):
            department = request.args.get('department', '')
            date_range = request.args.get('date_range', 'current')
            group_by = request.args.get('group_by', 'none')
            include_inactive = request.args.get('include_inactive', 'false') == 'true'
            export_format = request.args.get('export_format', 'csv')
        else:
            # Use form data for POST requests
            department = form.department.data
            date_range = form.date_range.data
            group_by = form.group_by.data
            include_inactive = form.include_inactive.data
            export_format = form.export_format.data
        
        # Get employees based on filters
        query = User.query
        
        # Filter by department if specified
        if department:
            query = query.filter_by(department=department)
        
        # Get all employees matching filters
        employees = query.all()
        
        # Get salaries for these employees
        data = []
        total_monthly = 0
        total_annual = 0
        
        for employee in employees:
            # Get the current salary (or most recent if no current)
            salary = EmployeeSalary.query.filter_by(employee_id=employee.id).order_by(EmployeeSalary.effective_date.desc()).first()
            
            if salary:
                # Skip inactive employees if not included
                if not include_inactive and not salary.is_active:
                    continue
                
                # Calculate monthly and annual values
                monthly_amount = salary.amount if salary.salary_type == 'monthly' else (
                    salary.amount / 12 if salary.salary_type == 'annual' else (salary.amount * 40 * 52 / 12)
                )
                annual_amount = salary.annualized_amount
                
                # Add to totals
                total_monthly += monthly_amount
                total_annual += annual_amount
                
                # Format data for display
                data.append({
                    'employee_id': employee.id,
                    'name': employee.get_display_name(),
                    'username': employee.username,
                    'department': employee.department.replace('_', ' ').title(),
                    'position': employee.profile.position if hasattr(employee, 'profile') and employee.profile else 'N/A',
                    'salary_type': salary.salary_type.title(),
                    'amount': salary.formatted_amount,
                    'raw_amount': salary.amount,
                    'currency': salary.currency,
                    'monthly_equivalent': monthly_amount,
                    'annual_equivalent': annual_amount,
                    'effective_date': salary.effective_date.strftime('%Y-%m-%d'),
                    'is_active': salary.is_active
                })
        
        # Group by if specified
        grouped_data = {}
        if group_by != 'none':
            for item in data:
                group_key = item[group_by]
                if group_key not in grouped_data:
                    grouped_data[group_key] = []
                grouped_data[group_key].append(item)
        else:
            grouped_data = {'all': data}
        
        # Create summary data
        summary = {
            'total_employees': len(data),
            'total_monthly': total_monthly,
            'total_annual': total_annual,
            'departments': len(set(item['department'] for item in data)),
            'avg_monthly': total_monthly / len(data) if data else 0,
            'avg_annual': total_annual / len(data) if data else 0,
        }
        
        # Export to CSV if requested
        if export_format == 'csv':
            output = io.StringIO()
            # Fix: Add 'raw_amount' to the fieldnames list
            writer = csv.DictWriter(output, fieldnames=[
                'employee_id', 'name', 'username', 'department', 'position', 
                'salary_type', 'amount', 'raw_amount', 'currency', 'monthly_equivalent', 
                'annual_equivalent', 'effective_date', 'is_active'
            ])
            writer.writeheader()
            writer.writerows(data)
            
            # Create response
            output.seek(0)
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            filename = f"salary_report_{timestamp}.csv"
            
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-disposition": f"attachment; filename={filename}"}
            )
            
        # Export to PDF if requested
        elif export_format == 'pdf':
            # Generate a timestamp for the filename
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            filename = f"salary_report_{timestamp}.pdf"
            
            # Create a temporary file path
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                temp_path = temp_file.name
                
            # Use ReportLab to generate PDF
            doc = SimpleDocTemplate(temp_path, pagesize=A4)
            styles = getSampleStyleSheet()
            elements = []
            
            # Title and header
            title_style = ParagraphStyle(
                'Title', 
                parent=styles['Heading1'],
                alignment=TA_CENTER,
                spaceAfter=20
            )
            
            # Add title
            elements.append(Paragraph(f"Employee Salary Report", title_style))
            elements.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}", styles['Normal']))
            elements.append(Spacer(1, 20))
            
            # Add summary section
            elements.append(Paragraph("Report Summary", styles['Heading2']))
            summary_data = [
                ["Total Employees", "Total Departments", "Avg Monthly", "Avg Annual"],
                [
                    str(summary['total_employees']),
                    str(summary['departments']),
                    f"${summary['avg_monthly']:.2f}",
                    f"${summary['avg_annual']:.2f}"
                ]
            ]
            
            summary_table = Table(summary_data, colWidths=[100, 100, 100, 100])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            elements.append(summary_table)
            elements.append(Spacer(1, 20))
            
            # Add each group of data
            for group_name, group_items in grouped_data.items():
                if len(grouped_data) > 1:
                    elements.append(Paragraph(f"{group_name} ({len(group_items)} employees)", styles['Heading3']))
                
                # Table headers
                table_data = [["Name", "Department", "Position", "Type", "Amount", "Monthly", "Annual"]]
                
                # Add data rows
                for item in group_items:
                    table_data.append([
                        item['name'],
                        item['department'],
                        item['position'],
                        item['salary_type'],
                        item['amount'],
                        f"{item['monthly_equivalent']:.2f} {item['currency']}",
                        f"{item['annual_equivalent']:.2f} {item['currency']}"
                    ])
                
                # Add summary row for this group
                total_monthly = sum(item['monthly_equivalent'] for item in group_items)
                total_annual = sum(item['annual_equivalent'] for item in group_items)
                table_data.append(["Group Total", "", "", "", "", f"{total_monthly:.2f} USD", f"{total_annual:.2f} USD"])
                
                # Create the table
                col_widths = [80, 70, 70, 50, 60, 80, 80]
                table = Table(table_data, colWidths=col_widths)
                
                # Style the table
                table.setStyle(TableStyle([
                    # Header row styles
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    
                    # Data rows
                    ('BACKGROUND', (0, 1), (-1, -2), colors.white),
                    ('ALIGN', (4, 1), (-1, -1), 'RIGHT'),  # Right-align numeric columns
                    
                    # Summary row
                    ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
                    ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
                    
                    # Borders
                    ('GRID', (0, 0), (-1, -2), 0.5, colors.grey),
                    ('LINEBELOW', (0, 0), (-1, 0), 1, colors.black),
                    ('LINEBELOW', (0, -2), (-1, -2), 1, colors.black),
                    ('BOX', (0, -1), (-1, -1), 1, colors.black),
                ]))
                
                elements.append(table)
                elements.append(Spacer(1, 15))  # Add space after table
            
            # Add footer
            elements.append(Spacer(1, 20))
            footer_text = "Confidential: This document contains sensitive compensation information and should be handled securely."
            elements.append(Paragraph(footer_text, styles['Italic']))
            
            # Build the PDF document
            doc.build(elements)
            
            # Return the PDF file as a response
            return send_file(
                temp_path,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )
        
        # Default to HTML view
        return render_template(
            'reports/salary_report_results.html',
            data=data,
            grouped_data=grouped_data,
            summary=summary,
            form=form,
            now=datetime.now()
        )
    
    return render_template('reports/salary_report.html', form=form)

@app.route('/employees/<int:employee_id>/salary', methods=['GET', 'POST'])
@login_required
@hr_required
def manage_salary(employee_id):
    """Manage employee salary"""
    employee = User.query.get_or_404(employee_id)
    
    # Get current salary if it exists
    current_salary = EmployeeSalary.query.filter_by(
        employee_id=employee_id, end_date=None
    ).first()
    
    # Get salary history
    salary_history = EmployeeSalary.query.filter_by(
        employee_id=employee_id
    ).order_by(EmployeeSalary.effective_date.desc()).all()
    
    form = SalaryForm()
    
    if current_salary and request.method == 'GET':
        # Prefill form with current salary data if available
        form.salary_type.data = current_salary.salary_type
        form.currency.data = current_salary.currency
        form.amount.data = current_salary.amount
    
    if form.validate_on_submit():
        # If there's a current active salary, set its end date to the day before new effective date
        if current_salary and current_salary.effective_date < form.effective_date.data:
            end_date = form.effective_date.data - timedelta(days=1)
            current_salary.end_date = end_date
        
        # Create new salary record
        new_salary = EmployeeSalary(
            employee_id=employee_id,
            salary_type=form.salary_type.data,
            effective_date=form.effective_date.data,
            currency=form.currency.data,
            amount=form.amount.data,
            created_by=current_user.id
        )
        db.session.add(new_salary)
        db.session.commit()
        
        flash('Salary information updated successfully!', 'success')
        return redirect(url_for('manage_salary', employee_id=employee_id))
        
    return render_template('employees/salary.html', 
                          employee=employee, 
                          current_salary=current_salary, 
                          salary_history=salary_history, 
                          form=form)

@app.route('/employees/export', methods=['GET'])
@login_required
@hr_required
def export_employees():
    """Export employees list as CSV or PDF"""
    export_format = request.args.get('format', 'csv')
    
    # Base query - similar to employee_list
    query = User.query.join(User.profile, isouter=True)
    
    # Apply filters if provided in URL params
    search = request.args.get('search', '')
    department = request.args.get('department', '')
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                User.username.like(search_term),
                User.email.like(search_term),
                EmployeeProfile.first_name.like(search_term),
                EmployeeProfile.last_name.like(search_term)
            )
        )
    
    if department:
        query = query.filter(User.department == department)
    
    # Get employees (exclude admins if current user is HR but not admin)
    if current_user.is_admin():
        employees = query.order_by(User.username).all()
    else:
        employees = query.filter(User.role != 'admin').order_by(User.username).all()
    
    # Prepare data for export
    data = []
    for employee in employees:
        employee_data = {
            'employee_id': employee.id,
            'username': employee.username,
            'email': employee.email,
            'department': employee.department.replace('_', ' ').title(),
            'role': employee.role.title(),
            'first_name': employee.profile.first_name if hasattr(employee, 'profile') and employee.profile else '',
            'last_name': employee.profile.last_name if hasattr(employee, 'profile') and employee.profile else '',
            'position': employee.profile.position if hasattr(employee, 'profile') and employee.profile else '',
            'hire_date': employee.profile.hire_date.strftime('%Y-%m-%d') if hasattr(employee, 'profile') and employee.profile and employee.profile.hire_date else '',
            'phone_number': employee.profile.phone_number if hasattr(employee, 'profile') and employee.profile else ''
        }
        data.append(employee_data)
    
    # Generate timestamp for filename
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    
    if export_format == 'csv':
        # Export to CSV
        output = io.StringIO()
        fieldnames = ['employee_id', 'username', 'email', 'first_name', 'last_name', 
                     'department', 'position', 'role', 'hire_date', 'phone_number']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
        
        # Create response
        output.seek(0)
        filename = f"employee_directory_{timestamp}.csv"
        
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename={filename}"}
        )
        
    elif export_format == 'pdf':
        # Create a temporary file for the PDF
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
            temp_path = temp_file.name
        
        # Create the PDF document
        doc = SimpleDocTemplate(temp_path, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Title and header
        title = "Employee Directory"
        date_str = datetime.now().strftime('%B %d, %Y')
        
        elements.append(Paragraph(title, styles['Title']))
        elements.append(Paragraph(f"Generated on {date_str}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Add filter information if any
        if search or department:
            filter_text = "Filters: "
            if search:
                filter_text += f"Search term: '{search}' "
            if department:
                filter_text += f"Department: '{department.replace('_', ' ').title()}'"
            elements.append(Paragraph(filter_text, styles['Italic']))
            elements.append(Spacer(1, 10))
        
        # Table data
        table_data = [
            ["Name", "Username", "Email", "Department", "Position", "Role", "Hire Date"]
        ]
        
        # Add employee data
        for emp in data:
            name = f"{emp['first_name']} {emp['last_name']}".strip()
            if not name:
                name = emp['username']
                
            table_data.append([
                name,
                emp['username'],
                emp['email'],
                emp['department'],
                emp['position'],
                emp['role'],
                emp['hire_date']
            ])
        
        # Create the table
        table = Table(table_data)
        
        # Apply styles to the table
        table.setStyle(TableStyle([
            # Header row
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            
            # Data rows - alternate row colors
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            
            # Add grids
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        # Add table to elements
        elements.append(table)
        
        # Footer
        elements.append(Spacer(1, 20))
        footer_text = "Confidential: This document contains employee information and should be handled according to HR policies."
        elements.append(Paragraph(footer_text, styles['Italic']))
        
        # Build the PDF
        doc.build(elements)
        
        # Return the PDF file as a download
        filename = f"employee_directory_{timestamp}.pdf"
        
        return send_file(
            temp_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    
    else:
        flash('Invalid export format', 'error')
        return redirect(url_for('employee_list'))

# Add routes for chatbot
@app.route('/api/chatbot/message', methods=['POST'])
@login_required
def chatbot_message():
    """Process a message from the user to the chatbot"""
    data = request.json
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'status': 'error', 'message': 'Message is required'})
    
    # Pass the current user ID for personalization
    response = chatbot.get_response(user_message, current_user.id)
    return jsonify(response)

@app.route('/api/chatbot/reset', methods=['POST'])
@login_required
def chatbot_reset():
    """Reset the chatbot conversation"""
    # Reset conversation for the current user
    response = chatbot.reset_conversation(current_user.id)
    return jsonify(response)

@app.route('/api/chatbot/user-info/<info_type>', methods=['GET'])
@login_required
def chatbot_user_info(info_type):
    """Get specific user information for the chatbot"""
    if info_type not in ['leave_balance', 'upcoming_trainings', 'pending_leaves']:
        return jsonify({'status': 'error', 'message': 'Invalid information type'})
        
    response = chatbot.get_user_info(current_user.id, info_type)
    return jsonify(response)

# Make sure static files are served correctly
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(os.path.join(app.root_path, 'static'), filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will create the LoginAttempt table as well
    app.run(debug=True)