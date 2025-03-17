"""
HR System Chatbot using Google Gemini API with user data integration
"""
import os
import json
from dotenv import load_dotenv
from google import genai
from flask_login import current_user
from models import db, User, EmployeeProfile, LeaveRequest, TrainingEnrollment

# Load environment variables
load_dotenv()

# Initialize Gemini API client
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

class HRChatbot:
    """HR System Chatbot powered by Google Gemini API with user data integration"""
    
    def __init__(self):
        self.model_name = "gemini-2.0-flash"
        self.history = {}  # Store conversation history per user
        self.base_system_prompt = """
        You are an AI assistant for an HR Management System. Your name is HR Assistant.
        
        Provide helpful information about:
        - HR policies and procedures
        - Employee benefits and time off
        - Training programs
        - Company policies
        
        Keep responses brief, professional, and helpful. If you don't know the answer,
        suggest contacting the HR department directly. Don't disclose confidential 
        employee information or make specific promises about benefits/policies
        that might vary by company.
        
        When asked about technical support or IT issues, direct users to the IT helpdesk.
        """
    
    def get_user_context(self, user_id):
        """Get personalized context for the current user"""
        try:
            # Get user info
            user = User.query.get(user_id)
            if not user:
                return {}
            
            # Get user profile
            profile = EmployeeProfile.query.filter_by(user_id=user_id).first()
            
            # Get pending leave requests
            pending_leaves = LeaveRequest.query.filter_by(
                employee_id=user_id, 
                status='pending'
            ).count()
            
            # Get upcoming trainings
            upcoming_trainings = TrainingEnrollment.query.filter_by(
                employee_id=user_id, 
                status='enrolled'
            ).join(TrainingEnrollment.training).filter(
                TrainingProgram.status.in_(['upcoming', 'in-progress'])
            ).count()
            
            # Create context object
            context = {
                "name": f"{profile.first_name} {profile.last_name}" if profile and profile.first_name else user.username,
                "username": user.username,
                "email": user.email,
                "department": user.department,
                "role": user.role,
                "position": profile.position if profile else None,
                "hire_date": profile.hire_date.strftime("%Y-%m-%d") if profile and profile.hire_date else None,
                "pending_leaves": pending_leaves,
                "upcoming_trainings": upcoming_trainings
            }
            
            return context
        except Exception as e:
            print(f"Error getting user context: {e}")
            return {}
    
    def get_personalized_system_prompt(self, user_id):
        """Create a personalized system prompt with user context"""
        user_context = self.get_user_context(user_id)
        
        if not user_context:
            return self.base_system_prompt
            
        context_prompt = f"""
        Currently assisting: {user_context.get('name', 'Unknown User')}
        Department: {user_context.get('department', 'Unknown')}
        Position: {user_context.get('position', 'Unknown')}
        Role: {user_context.get('role', 'employee')}
        
        User has {user_context.get('pending_leaves', 0)} pending leave requests.
        User has {user_context.get('upcoming_trainings', 0)} upcoming training enrollments.
        
        When the user asks about their information, you can use this context to provide personalized responses.
        Do not share this specific information unless directly asked about it.
        """
        
        return self.base_system_prompt + context_prompt
    
    def get_response(self, user_message, user_id):
        """Get a response from the Gemini model for the user message"""
        try:
            # Initialize history for user if not exists
            if user_id not in self.history:
                self.history[user_id] = []
                
            # Get personalized system prompt
            system_prompt = self.get_personalized_system_prompt(user_id)
            
            # Add user message to history
            self.history[user_id].append({"role": "user", "parts": [{"text": user_message}]})
            
            # Prepare the conversation history with system prompt
            conversation = [{"role": "model", "parts": [{"text": system_prompt}]}]
            conversation.extend(self.history[user_id])
            
            # Generate response using the client
            response = client.models.generate_content(
                model=self.model_name,
                contents=conversation
            )
            
            # Extract the text from the response
            response_text = response.text
            
            # Add model response to history
            self.history[user_id].append({"role": "model", "parts": [{"text": response_text}]})
            
            return {
                "status": "success",
                "message": response_text
            }
        except Exception as e:
            print(f"Gemini API error: {str(e)}")
            return {
                "status": "error",
                "message": "I'm having trouble connecting to my knowledge base. Please try again later."
            }
    
    def reset_conversation(self, user_id):
        """Reset the conversation history for a specific user"""
        if user_id in self.history:
            self.history[user_id] = []
        
        return {
            "status": "success",
            "message": "Conversation has been reset."
        }
    
    def get_user_info(self, user_id, info_type):
        """Get specific user information for predefined queries"""
        context = self.get_user_context(user_id)
        
        if info_type == 'leave_balance':
            # This would ideally come from a dedicated leave_balance table
            # For now, let's return a placeholder
            return {
                "status": "success",
                "annual_leave": 20,
                "sick_leave": 10,
                "personal_leave": 5,
                "used_annual": 5,
                "used_sick": 2,
                "used_personal": 1
            }
            
        elif info_type == 'upcoming_trainings':
            # Get actual upcoming training data
            trainings = TrainingEnrollment.query.filter_by(employee_id=user_id).all()
            training_data = []
            
            for enrollment in trainings:
                training_data.append({
                    "title": enrollment.training.title,
                    "start_date": enrollment.training.start_date.strftime("%Y-%m-%d"),
                    "end_date": enrollment.training.end_date.strftime("%Y-%m-%d"),
                    "status": enrollment.status
                })
                
            return {
                "status": "success",
                "trainings": training_data
            }
            
        elif info_type == 'pending_leaves':
            # Get actual pending leave data
            leaves = LeaveRequest.query.filter_by(
                employee_id=user_id,
                status='pending'
            ).all()
            
            leave_data = []
            for leave in leaves:
                leave_data.append({
                    "leave_type": leave.leave_type,
                    "start_date": leave.start_date.strftime("%Y-%m-%d"),
                    "end_date": leave.end_date.strftime("%Y-%m-%d"),
                    "duration_days": leave.duration_days
                })
                
            return {
                "status": "success",
                "leaves": leave_data
            }
            
        return {
            "status": "error",
            "message": "Information not available"
        }

# Create a singleton instance
chatbot = HRChatbot()
