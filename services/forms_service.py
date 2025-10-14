"""
Forms service module for PostgreSQL database
"""

import json
import uuid
import time
from datetime import datetime
from ..db.database import get_cursor

class FormsService:
    """Service for handling form operations with PostgreSQL"""
    
    @staticmethod
    def get_forms_by_user(user_id, limit=100, offset=0):
        """Get forms for a specific user"""
        with get_cursor() as cursor:
            query = """
                SELECT * FROM forms 
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """
            cursor.execute(query, (user_id, limit, offset))
            return cursor.fetchall()
    
    @staticmethod
    def get_form_by_id(form_id, user_id=None):
        """Get a form by ID, optionally checking user ownership"""
        with get_cursor() as cursor:
            query = "SELECT * FROM forms WHERE id = %s"
            params = [form_id]
            
            if user_id:
                query += " AND user_id = %s"
                params.append(user_id)
                
            cursor.execute(query, params)
            return cursor.fetchone()
    
    @staticmethod
    def create_form(user_id, form_data):
        """Create a new form"""
        form_id = str(uuid.uuid4())
        
        # Check if name already exists for this user
        canonical_name = FormsService.slugify_name(form_data.get('name', 'Untitled Form'))
        
        if FormsService.check_form_name_exists(user_id, canonical_name):
            # Append timestamp to make name unique
            timestamp = int(time.time())
            canonical_name = f"{canonical_name}-{timestamp}"
        
        with get_cursor(commit=True) as cursor:
            # Prepare form data
            now = datetime.now()
            
            # Convert JSON fields
            fields = json.dumps(form_data.get('fields', {}))
            theme = json.dumps(form_data.get('theme', {}))
            branding = json.dumps(form_data.get('branding', {}))
            allowed_domains = json.dumps(form_data.get('allowedDomains', []))
            
            query = """
                INSERT INTO forms (
                    id, user_id, title, name, description, form_type, 
                    is_published, views, submissions, submission_limit,
                    fields, theme, branding, allowed_domains, 
                    created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, 
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s
                ) RETURNING *
            """
            
            cursor.execute(query, (
                form_id,
                user_id,
                form_data.get('title', 'Untitled Form'),
                canonical_name,
                form_data.get('description', ''),
                form_data.get('formType', 'simple'),
                form_data.get('isPublished', False),
                0,  # views
                0,  # submissions
                form_data.get('submissionLimit', 0),
                fields,
                theme,
                branding,
                allowed_domains,
                now,
                now
            ))
            
            # Update user's forms count
            FormsService.increment_user_forms_count(user_id)
            
            return cursor.fetchone()
    
    @staticmethod
    def update_form(form_id, user_id, form_data):
        """Update an existing form"""
        with get_cursor(commit=True) as cursor:
            # First check if form exists and belongs to user
            check_query = "SELECT id FROM forms WHERE id = %s AND user_id = %s"
            cursor.execute(check_query, (form_id, user_id))
            if not cursor.fetchone():
                return None
            
            # Prepare update fields
            update_fields = []
            params = []
            
            # Map form_data keys to database columns
            field_mapping = {
                'title': 'title',
                'name': 'name',
                'description': 'description',
                'formType': 'form_type',
                'isPublished': 'is_published',
                'submissionLimit': 'submission_limit',
                'fields': 'fields',
                'theme': 'theme',
                'branding': 'branding',
                'allowedDomains': 'allowed_domains'
            }
            
            for key, db_column in field_mapping.items():
                if key in form_data:
                    value = form_data[key]
                    
                    # Convert JSON fields
                    if key in ['fields', 'theme', 'branding', 'allowedDomains']:
                        value = json.dumps(value)
                    
                    update_fields.append(f"{db_column} = %s")
                    params.append(value)
            
            # Add updated_at timestamp
            update_fields.append("updated_at = %s")
            params.append(datetime.now())
            
            # Add form_id and user_id to params
            params.extend([form_id, user_id])
            
            # Build and execute update query
            query = f"""
                UPDATE forms 
                SET {', '.join(update_fields)}
                WHERE id = %s AND user_id = %s
                RETURNING *
            """
            
            cursor.execute(query, params)
            return cursor.fetchone()
    
    @staticmethod
    def delete_form(form_id, user_id):
        """Delete a form and all related data"""
        with get_cursor(commit=True) as cursor:
            # First check if form exists and belongs to user
            check_query = "SELECT id FROM forms WHERE id = %s AND user_id = %s"
            cursor.execute(check_query, (form_id, user_id))
            if not cursor.fetchone():
                return False
            
            # Delete form (cascading will delete related data)
            query = "DELETE FROM forms WHERE id = %s AND user_id = %s"
            cursor.execute(query, (form_id, user_id))
            
            # Decrement user's forms count
            FormsService.decrement_user_forms_count(user_id)
            
            return True
    
    @staticmethod
    def toggle_form_publish(form_id, user_id, publish_status=None):
        """Toggle or set a form's publish status"""
        with get_cursor(commit=True) as cursor:
            # First check if form exists and belongs to user
            check_query = "SELECT is_published FROM forms WHERE id = %s AND user_id = %s"
            cursor.execute(check_query, (form_id, user_id))
            form = cursor.fetchone()
            
            if not form:
                return {"success": False, "error": "Form not found or not authorized"}
            
            current_status = form['is_published']
            
            # Determine new status
            if publish_status is None:
                # Toggle current status
                new_status = not current_status
            else:
                # Set to specified status
                new_status = publish_status
            
            # Check if already in desired state
            if current_status == new_status:
                return {
                    "success": True, 
                    "isPublished": new_status,
                    "alreadyInDesiredState": True
                }
            
            # Update publish status
            query = """
                UPDATE forms 
                SET is_published = %s, updated_at = %s
                WHERE id = %s AND user_id = %s
                RETURNING *
            """
            
            cursor.execute(query, (new_status, datetime.now(), form_id, user_id))
            updated_form = cursor.fetchone()
            
            return {
                "success": True,
                "isPublished": updated_form['is_published'],
                "alreadyInDesiredState": False
            }
    
    @staticmethod
    def get_form_submissions(form_id, user_id, limit=100, offset=0):
        """Get submissions for a specific form"""
        with get_cursor() as cursor:
            # First check if form exists and belongs to user
            check_query = "SELECT id FROM forms WHERE id = %s AND user_id = %s"
            cursor.execute(check_query, (form_id, user_id))
            if not cursor.fetchone():
                return []
            
            # Get submissions
            query = """
                SELECT * FROM submissions 
                WHERE form_id = %s
                ORDER BY submitted_at DESC
                LIMIT %s OFFSET %s
            """
            cursor.execute(query, (form_id, limit, offset))
            return cursor.fetchall()
    
    @staticmethod
    def increment_form_views(form_id):
        """Increment a form's view count"""
        with get_cursor(commit=True) as cursor:
            query = """
                UPDATE forms 
                SET views = views + 1
                WHERE id = %s
            """
            cursor.execute(query, (form_id,))
    
    @staticmethod
    def increment_form_submissions(form_id):
        """Increment a form's submission count"""
        with get_cursor(commit=True) as cursor:
            query = """
                UPDATE forms 
                SET submissions = submissions + 1
                WHERE id = %s
            """
            cursor.execute(query, (form_id,))
    
    @staticmethod
    def increment_user_forms_count(user_id):
        """Increment a user's forms count"""
        with get_cursor(commit=True) as cursor:
            query = """
                UPDATE users 
                SET forms_count = forms_count + 1
                WHERE uid = %s
            """
            cursor.execute(query, (user_id,))
    
    @staticmethod
    def decrement_user_forms_count(user_id):
        """Decrement a user's forms count"""
        with get_cursor(commit=True) as cursor:
            query = """
                UPDATE users 
                SET forms_count = GREATEST(forms_count - 1, 0)
                WHERE uid = %s
            """
            cursor.execute(query, (user_id,))
    
    @staticmethod
    def check_form_name_exists(user_id, name):
        """Check if a form name already exists for a user"""
        with get_cursor() as cursor:
            query = "SELECT id FROM forms WHERE user_id = %s AND name = %s"
            cursor.execute(query, (user_id, name))
            return cursor.fetchone() is not None
    
    @staticmethod
    def slugify_name(name):
        """Convert a form name to a URL-friendly slug"""
        # Simple implementation - replace spaces with hyphens and lowercase
        return name.lower().replace(' ', '-')