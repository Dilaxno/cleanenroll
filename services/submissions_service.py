"""
Submissions service module for PostgreSQL database
"""

import json
import uuid
from datetime import datetime
from ..db.database import get_cursor
from .forms_service import FormsService

class SubmissionsService:
    """Service for handling form submissions with PostgreSQL"""
    
    @staticmethod
    def create_submission(form_id, submission_data, metadata=None):
        """Create a new form submission"""
        submission_id = str(uuid.uuid4())
        
        with get_cursor(commit=True) as cursor:
            # First get the form to check if it exists and get owner_id
            form_query = "SELECT user_id, is_published, submission_limit, submissions FROM forms WHERE id = %s"
            cursor.execute(form_query, (form_id,))
            form = cursor.fetchone()
            
            if not form:
                return {"success": False, "error": "Form not found"}
            
            # Check if form is published
            if not form['is_published']:
                return {"success": False, "error": "Form is not published"}
            
            # Check submission limit
            if form['submission_limit'] > 0 and form['submissions'] >= form['submission_limit']:
                return {"success": False, "error": "Submission limit reached"}
            
            # Prepare submission data
            now = datetime.now()
            
            # Extract metadata fields
            ip_address = None
            country_code = None
            user_agent = None
            
            if metadata:
                ip_address = metadata.get('ipAddress')
                country_code = metadata.get('countryCode')
                user_agent = metadata.get('userAgent')
            
            # Insert submission
            query = """
                INSERT INTO submissions (
                    id, form_id, form_owner_id, data, metadata,
                    ip_address, country_code, user_agent, submitted_at
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                ) RETURNING *
            """
            
            cursor.execute(query, (
                submission_id,
                form_id,
                form['user_id'],
                json.dumps(submission_data),
                json.dumps(metadata or {}),
                ip_address,
                country_code,
                user_agent,
                now
            ))
            
            # Increment form submission count
            FormsService.increment_form_submissions(form_id)
            
            return {"success": True, "submission": cursor.fetchone()}
    
    @staticmethod
    def get_submission(submission_id, user_id=None):
        """Get a submission by ID, optionally checking user ownership"""
        with get_cursor() as cursor:
            query = """
                SELECT s.* FROM submissions s
                JOIN forms f ON s.form_id = f.id
                WHERE s.id = %s
            """
            params = [submission_id]
            
            if user_id:
                query += " AND f.user_id = %s"
                params.append(user_id)
                
            cursor.execute(query, params)
            return cursor.fetchone()
    
    @staticmethod
    def delete_submission(submission_id, user_id):
        """Delete a submission, checking user ownership"""
        with get_cursor(commit=True) as cursor:
            # First check if submission exists and belongs to user's form
            check_query = """
                SELECT s.id, s.form_id FROM submissions s
                JOIN forms f ON s.form_id = f.id
                WHERE s.id = %s AND f.user_id = %s
            """
            cursor.execute(check_query, (submission_id, user_id))
            submission = cursor.fetchone()
            
            if not submission:
                return False
            
            # Delete submission
            query = "DELETE FROM submissions WHERE id = %s"
            cursor.execute(query, (submission_id,))
            
            # Decrement form submission count
            form_id = submission['form_id']
            decrement_query = """
                UPDATE forms 
                SET submissions = GREATEST(submissions - 1, 0)
                WHERE id = %s
            """
            cursor.execute(decrement_query, (form_id,))
            
            return True
    
    @staticmethod
    def get_dashboard_stats(user_id):
        """Get dashboard statistics for a user"""
        with get_cursor() as cursor:
            # Get form count
            forms_query = "SELECT COUNT(*) as form_count FROM forms WHERE user_id = %s"
            cursor.execute(forms_query, (user_id,))
            form_count = cursor.fetchone()['form_count']
            
            # Get total submissions
            submissions_query = """
                SELECT COUNT(*) as submission_count FROM submissions s
                JOIN forms f ON s.form_id = f.id
                WHERE f.user_id = %s
            """
            cursor.execute(submissions_query, (user_id,))
            submission_count = cursor.fetchone()['submission_count']
            
            # Get total views
            views_query = "SELECT SUM(views) as total_views FROM forms WHERE user_id = %s"
            cursor.execute(views_query, (user_id,))
            result = cursor.fetchone()
            total_views = result['total_views'] or 0
            
            # Get recent submissions
            recent_query = """
                SELECT s.*, f.title as form_title FROM submissions s
                JOIN forms f ON s.form_id = f.id
                WHERE f.user_id = %s
                ORDER BY s.submitted_at DESC
                LIMIT 5
            """
            cursor.execute(recent_query, (user_id,))
            recent_submissions = cursor.fetchall()
            
            return {
                "formCount": form_count,
                "submissionCount": submission_count,
                "totalViews": total_views,
                "recentSubmissions": recent_submissions
            }