"""
Async Forms service module with Pydantic validation for PostgreSQL database
"""

import json
import uuid
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_session
from backend.models.validators import validate_form, sanitize_for_db
from backend.models.base import FormModel
from backend.db.validation import validate_and_save_form

class AsyncFormsService:
    """Async service for handling form operations with PostgreSQL and Pydantic validation"""
    
    @staticmethod
    async def get_forms_by_user(session: AsyncSession, user_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get forms for a specific user"""
        query = text("""
            SELECT * FROM forms 
            WHERE user_id = :user_id
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """)
        
        result = await session.execute(
            query, 
            {"user_id": user_id, "limit": limit, "offset": offset}
        )
        
        return [dict(row) for row in result.mappings().all()]
    
    @staticmethod
    async def get_form_by_id(session: AsyncSession, form_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get a form by ID, optionally checking user ownership"""
        query_text = "SELECT * FROM forms WHERE id = :form_id"
        params = {"form_id": form_id}
        
        if user_id:
            query_text += " AND user_id = :user_id"
            params["user_id"] = user_id
            
        query = text(query_text)
        result = await session.execute(query, params)
        row = result.mappings().first()
        
        return dict(row) if row else None
    
    @staticmethod
    async def check_form_name_exists(session: AsyncSession, user_id: str, name: str) -> bool:
        """Check if a form name already exists for a user"""
        query = text("""
            SELECT COUNT(*) as count FROM forms 
            WHERE user_id = :user_id AND name = :name
        """)
        
        result = await session.execute(query, {"user_id": user_id, "name": name})
        row = result.mappings().first()
        
        return row["count"] > 0 if row else False
    
    @staticmethod
    def slugify_name(name: str) -> str:
        """Convert a form name to a URL-friendly slug"""
        # Simple slugify implementation
        import re
        slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
        return slug or 'untitled-form'
    
    @staticmethod
    async def increment_user_forms_count(session: AsyncSession, user_id: str) -> None:
        """Increment the user's forms count"""
        query = text("""
            UPDATE users 
            SET forms_count = forms_count + 1 
            WHERE uid = :user_id
        """)
        
        await session.execute(query, {"user_id": user_id})
    
    @staticmethod
    async def create_form(session: AsyncSession, form_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new form with Pydantic validation
        
        Args:
            session: SQLAlchemy async session
            form_data: Form data to validate and save
            
        Returns:
            Created form data
            
        Raises:
            HTTPException: If validation fails
        """
        # Generate UUID for the form
        if 'id' not in form_data:
            form_data['id'] = str(uuid.uuid4())
            
        # Check if name already exists for this user
        user_id = form_data.get('user_id')
        canonical_name = AsyncFormsService.slugify_name(form_data.get('name', 'Untitled Form'))
        
        if await AsyncFormsService.check_form_name_exists(session, user_id, canonical_name):
            # Append timestamp to make name unique
            timestamp = int(time.time())
            canonical_name = f"{canonical_name}-{timestamp}"
            form_data['name'] = canonical_name
        
        # Validate form data with Pydantic
        is_valid, result = validate_form(form_data)
        
        if not is_valid:
            # Return validation errors
            return {"errors": result}
        
        # Convert validated model to dict for database operation
        validated_data = sanitize_for_db(result)
        
        # Set timestamps
        now = datetime.now()
        if 'created_at' not in validated_data:
            validated_data['created_at'] = now
        if 'updated_at' not in validated_data:
            validated_data['updated_at'] = now
            
        # Convert complex objects to JSON strings for database
        for json_field in ['fields', 'theme', 'branding', 'allowed_domains']:
            if json_field in validated_data and not isinstance(validated_data[json_field], str):
                validated_data[json_field] = json.dumps(validated_data[json_field])
        
        # Build the query dynamically based on the validated data
        columns = ', '.join(validated_data.keys())
        placeholders = ', '.join(f':{key}' for key in validated_data.keys())
        
        query = text(f"""
            INSERT INTO forms ({columns})
            VALUES ({placeholders})
            RETURNING *
        """)
        
        result = await session.execute(query, validated_data)
        await session.commit()
        
        # Update user's forms count
        await AsyncFormsService.increment_user_forms_count(session, user_id)
        
        # Return the created form
        created_form = result.mappings().first()
        return dict(created_form) if created_form else None
    
    @staticmethod
    async def update_form(session: AsyncSession, form_id: str, user_id: str, form_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Update a form with Pydantic validation
        
        Args:
            session: SQLAlchemy async session
            form_id: ID of the form to update
            user_id: ID of the form owner
            form_data: Form data to validate and update
            
        Returns:
            Updated form data or None if form not found
            
        Raises:
            HTTPException: If validation fails
        """
        # Check if form exists and belongs to user
        existing_form = await AsyncFormsService.get_form_by_id(session, form_id, user_id)
        if not existing_form:
            return None
            
        # Merge existing data with updates
        update_data = {**existing_form, **form_data, 'id': form_id, 'user_id': user_id}
        
        # Validate the merged data
        is_valid, result = validate_form(update_data)
        
        if not is_valid:
            # Return validation errors
            return {"errors": result}
            
        # Convert validated model to dict for database operation
        validated_data = sanitize_for_db(result)
        
        # Set updated timestamp
        validated_data['updated_at'] = datetime.now()
        
        # Convert complex objects to JSON strings for database
        for json_field in ['fields', 'theme', 'branding', 'allowed_domains']:
            if json_field in validated_data and not isinstance(validated_data[json_field], str):
                validated_data[json_field] = json.dumps(validated_data[json_field])
        
        # Remove id and user_id from the update fields
        validated_data.pop('id', None)
        validated_data.pop('user_id', None)
        
        if not validated_data:
            # No fields to update
            return existing_form
            
        # Build the SET clause for the UPDATE query
        set_clause = ', '.join(f"{key} = :{key}" for key in validated_data.keys())
        
        query = text(f"""
            UPDATE forms
            SET {set_clause}
            WHERE id = :form_id AND user_id = :user_id
            RETURNING *
        """)
        
        # Add form_id and user_id to parameters
        params = {**validated_data, 'form_id': form_id, 'user_id': user_id}
        
        result = await session.execute(query, params)
        await session.commit()
        
        updated_form = result.mappings().first()
        return dict(updated_form) if updated_form else None