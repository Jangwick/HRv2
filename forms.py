from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField, DateField, IntegerField, SelectMultipleField, RadioField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, NumberRange
from flask_wtf.file import FileField, FileAllowed
from models import User
from wtforms.fields import FloatField
from wtforms.validators import NumberRange, Optional

class LoginForm(FlaskForm):
    # Change from email to username_or_email
    username_or_email = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    department = SelectField('Department', choices=[
        ('Engineering', 'Engineering'),
        ('Marketing', 'Marketing'),
        ('Finance', 'Finance'),
        ('Hr', 'Human Resources'),
        ('Operations', 'Operations'),
        ('IT', 'Information Technology'),
        ('Sales', 'Sales'),
        ('Customer_support', 'Customer Support')
    ], validators=[DataRequired()])
    role = SelectField('Account Type', choices=[
        ('employee', 'Employee'),
        ('hr', 'HR'),
        ('admin', 'Administrator')
    ], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class ProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=50)])
    phone_number = StringField('Phone Number', validators=[Length(max=20)])
    address = StringField('Address', validators=[Length(max=200)])
    city = StringField('City', validators=[Length(max=50)])
    country = StringField('Country', validators=[Length(max=50)])
    bio = TextAreaField('Bio')
    position = StringField('Position', validators=[Length(max=100)])
    hire_date = DateField('Hire Date', format='%Y-%m-%d', validators=[DataRequired()])
    birth_date = DateField('Birth Date', format='%Y-%m-%d')
    profile_image = FileField('Profile Picture', validators=[
        FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')
    ])
    submit = SubmitField('Update Profile')

class EmployeeSearchForm(FlaskForm):
    search = StringField('Search', validators=[Length(max=100)])
    department = SelectField('Department', choices=[
        ('', 'All Departments'),
        ('engineering', 'Engineering'),
        ('marketing', 'Marketing'),
        ('finance', 'Finance'),
        ('hr', 'Human Resources'),
        ('operations', 'Operations'),
        ('it', 'Information Technology'),
        ('sales', 'Sales'),
        ('customer_support', 'Customer Support')
    ], validators=[])
    submit = SubmitField('Search')

class LeaveRequestForm(FlaskForm):
    leave_type = SelectField('Leave Type', choices=[
        ('vacation', 'Vacation Leave'),
        ('sick', 'Sick Leave'),
        ('personal', 'Personal Leave'),
        ('bereavement', 'Bereavement Leave'),
        ('maternity', 'Maternity Leave'),
        ('paternity', 'Paternity Leave'),
        ('unpaid', 'Unpaid Leave')
    ], validators=[DataRequired()])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    reason = TextAreaField('Reason for Leave', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Submit Request')
    
    def validate_end_date(self, field):
        """Ensure end_date is not before start_date"""
        if field.data < self.start_date.data:
            raise ValidationError('End date cannot be before start date.')

class LeaveApprovalForm(FlaskForm):
    status = SelectField('Status', choices=[
        ('approved', 'Approve'),
        ('denied', 'Deny')
    ], validators=[DataRequired()])
    comment = TextAreaField('Comment', validators=[Length(max=500)])
    submit = SubmitField('Submit Decision')

class TrainingProgramForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    instructor = StringField('Instructor', validators=[DataRequired(), Length(max=100)])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired(), Length(max=100)])
    max_participants = IntegerField('Maximum Participants (0 for unlimited)', default=0, validators=[NumberRange(min=0)])
    category = SelectField('Category', choices=[
        ('technical', 'Technical Skills'),
        ('soft_skills', 'Soft Skills'),
        ('leadership', 'Leadership'),
        ('compliance', 'Compliance'),
        ('safety', 'Safety'),
        ('professional', 'Professional Development')
    ], validators=[DataRequired()])
    status = SelectField('Status', choices=[
        ('upcoming', 'Upcoming'),
        ('in-progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled')
    ], validators=[DataRequired()])
    submit = SubmitField('Save Training Program')
    
    def validate_end_date(self, field):
        """Ensure end_date is not before start_date"""
        if field.data < self.start_date.data:
            raise ValidationError('End date cannot be before start date.')

class EnrollmentForm(FlaskForm):
    employees = SelectMultipleField('Select Employees', coerce=int)
    submit = SubmitField('Enroll Selected Employees')

class TrainingFeedbackForm(FlaskForm):
    rating = RadioField('Rating', choices=[
        ('1', '1 - Very Poor'),
        ('2', '2 - Poor'),
        ('3', '3 - Average'),
        ('4', '4 - Good'),
        ('5', '5 - Excellent')
    ], validators=[DataRequired()], coerce=int)
    feedback = TextAreaField('Feedback', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Submit Feedback')

class SalaryForm(FlaskForm):
    amount = FloatField('Salary Amount', validators=[DataRequired(), NumberRange(min=0)])
    currency = SelectField('Currency', choices=[
        ('USD', 'USD - US Dollar'),
        ('EUR', 'EUR - Euro'),
        ('GBP', 'GBP - British Pound'),
        ('JPY', 'JPY - Japanese Yen'),
        ('CAD', 'CAD - Canadian Dollar'),
        ('AUD', 'AUD - Australian Dollar')
    ])
    salary_type = SelectField('Salary Type', choices=[
        ('monthly', 'Monthly'),
        ('annual', 'Annual'),
        ('hourly', 'Hourly')
    ])
    effective_date = DateField('Effective Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Save Salary')

class SalaryReportForm(FlaskForm):
    department = SelectField('Department', choices=[
        ('', 'All Departments'),
        ('engineering', 'Engineering'),
        ('marketing', 'Marketing'),
        ('finance', 'Finance'),
        ('hr', 'Human Resources'),
        ('operations', 'Operations'),
        ('it', 'Information Technology'),
        ('sales', 'Sales'),
        ('customer_support', 'Customer Support')
    ])
    date_range = SelectField('Date Range', choices=[
        ('current', 'Current Salaries'),
        ('year', 'Current Year'),
        ('last_year', 'Last Year'),
        ('custom', 'Custom Range')
    ])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[Optional()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[Optional()])
    group_by = SelectField('Group By', choices=[
        ('none', 'No Grouping'),
        ('department', 'Department'),
        ('salary_type', 'Salary Type')
    ])
    include_inactive = BooleanField('Include Inactive Employees')
    export_format = SelectField('Export Format', choices=[
        ('html', 'Web View'),
        ('csv', 'CSV File'),
        ('pdf', 'PDF File')
    ])
    submit = SubmitField('Generate Report')
