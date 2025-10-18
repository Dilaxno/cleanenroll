"""
Submissions service module for PostgreSQL database
"""

import json
import uuid
from datetime import datetime
from ..db.database import get_cursor
from .forms_service import FormsService
from ..utils.encryption import encrypt_submission_data, decrypt_submission_data

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
            
            # Encrypt submission data before storing
            try:
                encrypted_data = encrypt_submission_data(submission_data)
            except Exception as e:
                print(f"Encryption error: {e}")
                return {"success": False, "error": "Failed to encrypt submission data"}
            
            # Insert submission with encrypted data
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
                encrypted_data,  # Store encrypted data instead of plaintext
                json.dumps(metadata or {}),
                ip_address,
                country_code,
                user_agent,
                now
            ))
            
            # Increment form submission count
            FormsService.increment_form_submissions(form_id)
            
            # Record analytics data
            try:
                from datetime import date
                today = date.today()
                
                # Update country analytics (aggregate per day)
                if country_code:
                    analytics_query = """
                        INSERT INTO form_countries_analytics (form_id, day, country_iso2, count)
                        VALUES (%s, %s, %s, 1)
                        ON CONFLICT (form_id, day, country_iso2)
                        DO UPDATE SET count = form_countries_analytics.count + 1
                    """
                    cursor.execute(analytics_query, (form_id, today, country_code.upper()))
                
                # Record submission marker for map visualization
                lat = metadata.get('lat') if metadata else None
                lon = metadata.get('lon') if metadata else None
                if lat is not None and lon is not None:
                    marker_query = """
                        INSERT INTO submission_markers (
                            id, form_id, response_id, lat, lon, country_code, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """
                    marker_id = str(uuid.uuid4())
                    cursor.execute(marker_query, (
                        marker_id,
                        form_id,
                        submission_id,
                        float(lat),
                        float(lon),
                        country_code.upper() if country_code else None,
                        now
                    ))
            except Exception as e:
                # Don't fail submission if analytics fails
                print(f"Analytics recording error: {e}")
            
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
            submission = cursor.fetchone()
            
            # Decrypt submission data before returning
            if submission and submission.get('data'):
                try:
                    encrypted_data = submission['data']
                    # Data is stored as encrypted string, decrypt it
                    if isinstance(encrypted_data, str):
                        decrypted_data = decrypt_submission_data(encrypted_data)
                        submission['data'] = json.dumps(decrypted_data) if isinstance(decrypted_data, dict) else decrypted_data
                except Exception as e:
                    print(f"Decryption error: {e}")
                    # Return None or original data based on security policy
                    # For security, we don't return encrypted data
                    submission['data'] = None
            
            return submission
    
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