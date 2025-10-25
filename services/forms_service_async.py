"""
Async Forms service module with Pydantic validation for PostgreSQL database
"""

import json
import uuid
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import text, Integer, String, bindparam
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_session
from models.validators import validate_form, sanitize_for_db
from models.base import FormModel
from db.validation import validate_and_save_form
from utils.data_normalization import normalize_booleans

class AsyncFormsService:
    """Async service for handling form operations with PostgreSQL and Pydantic validation"""
    
    @staticmethod
    async def get_forms_by_user(session: AsyncSession, user_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get forms for a specific user with actual submission and view counts from database"""
        # Normalize pagination values and bind explicit types to avoid driver ambiguity
        safe_limit = int(limit) if isinstance(limit, int) else 100
        safe_offset = max(0, int(offset) if isinstance(offset, int) else 0)

        # Query forms with actual counts from submissions and analytics tables
        # This ensures we show ALL submissions/views from Neon DB, not cached counters
        # Also calculates conversion rate (submissions/views * 100)
        query = (
            text(
                """
                SELECT 
                    f.*,
                    COALESCE(s.submission_count, 0) as submissions,
                    COALESCE(v.view_count, 0) as views,
                    s.last_submission_at,
                    CASE 
                        WHEN COALESCE(v.view_count, 0) > 0 
                        THEN ROUND((COALESCE(s.submission_count, 0)::numeric / v.view_count::numeric * 100), 1)
                        ELSE 0 
                    END as conversion_rate
                FROM forms f
                LEFT JOIN (
                    SELECT form_id, COUNT(*) as submission_count, MAX(submitted_at) as last_submission_at
                    FROM submissions
                    GROUP BY form_id
                ) s ON f.id = s.form_id
                LEFT JOIN (
                    SELECT form_id, COUNT(*) as view_count
                    FROM analytics
                    WHERE type = 'view'
                    GROUP BY form_id
                ) v ON f.id = v.form_id
                WHERE f.user_id = :user_id
                ORDER BY f.created_at DESC
                LIMIT :limit_val OFFSET :offset_val
                """
            )
            .bindparams(
                bindparam("user_id", type_=String),
                bindparam("limit_val", type_=Integer),
                bindparam("offset_val", type_=Integer),
            )
        )

        result = await session.execute(
            query,
            {"user_id": user_id, "limit_val": safe_limit, "offset_val": safe_offset},
        )
        
        # Normalize all booleans in JSONB fields (theme, fields, etc.) for each form
        forms = [dict(row) for row in result.mappings().all()]
        return [normalize_booleans(form) for form in forms]
    
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
        
        if row:
            data = dict(row)
            # Convert snake_case DB columns to camelCase for frontend (Builder)
            # Ensure all boolean fields default to False (not None) for consistent frontend behavior
            form_data = {
                "id": data.get("id"),
                "userId": data.get("user_id"),
                "title": data.get("title"),
                "name": data.get("name"),
                "description": data.get("description"),
                "formType": data.get("form_type") or "simple",
                "isPublished": bool(data.get("is_published")),
                "views": data.get("views") or 0,
                "submissions": data.get("submissions") or 0,
                "submissionLimit": data.get("submission_limit") or 0,
                "fields": data.get("fields") or [],
                "theme": data.get("theme") or {},
                "branding": data.get("branding") or {},
                "allowedDomains": data.get("allowed_domains") or [],
                # Settings fields - all booleans default to False when NULL
                "language": data.get("language") or "en",
                "thankYouMessage": data.get("thank_you_message") or "",
                "thankYouDisplay": data.get("thank_you_display") or "page",
                "celebrationEnabled": bool(data.get("celebration_enabled")) if data.get("celebration_enabled") is not None else False,
                "showTopProgress": bool(data.get("show_top_progress")) if data.get("show_top_progress") is not None else False,
                "showKeyboardHints": bool(data.get("show_keyboard_hints")) if data.get("show_keyboard_hints") is not None else False,
                # Auto-reply - booleans default to False
                "autoReplyEnabled": bool(data.get("auto_reply_enabled")) if data.get("auto_reply_enabled") is not None else False,
                "autoReplyEmailFieldId": data.get("auto_reply_email_field_id") or "",
                "autoReplySubject": data.get("auto_reply_subject") or "",
                "autoReplyMessageHtml": data.get("auto_reply_message_html") or "",
                "autoReplyMessageText": data.get("auto_reply_message_text") or "",
                "autoReplyContentMode": data.get("auto_reply_content_mode") or "html",
                "autoReplyFooterHtml": data.get("auto_reply_footer_html") or "",
                "autoReplyButtonLabel": data.get("auto_reply_button_label") or "",
                "autoReplyButtonUrl": data.get("auto_reply_button_url") or "",
                "autoReplyButtonColor": data.get("auto_reply_button_color") or "#4f46e5",
                # Redirect
                "redirect": data.get("redirect"),
                # Email validation - all booleans default to False
                "emailValidationEnabled": bool(data.get("email_validation_enabled")) if data.get("email_validation_enabled") is not None else False,
                "professionalEmailsOnly": bool(data.get("professional_emails_only")) if data.get("professional_emails_only") is not None else False,
                "blockRoleEmails": bool(data.get("block_role_emails")) if data.get("block_role_emails") is not None else False,
                "emailRejectBadReputation": bool(data.get("email_reject_bad_reputation")) if data.get("email_reject_bad_reputation") is not None else False,
                "minDomainAgeDays": data.get("min_domain_age_days") or 30,
                # Duplicate prevention - all booleans default to False
                "preventDuplicateByUID": bool(data.get("prevent_duplicate_by_uid")) if data.get("prevent_duplicate_by_uid") is not None else False,
                "preventDuplicateByIP": bool(data.get("prevent_duplicate_by_ip")) if data.get("prevent_duplicate_by_ip") is not None else False,
                "duplicateWindowHours": data.get("duplicate_window_hours") or 24,
                # Security - all booleans default to False
                "recaptchaEnabled": bool(data.get("recaptcha_enabled")) if data.get("recaptcha_enabled") is not None else False,
                "urlScanEnabled": bool(data.get("url_scan_enabled")) if data.get("url_scan_enabled") is not None else False,
                "fileScanEnabled": bool(data.get("file_scan_enabled")) if data.get("file_scan_enabled") is not None else False,
                "gdprComplianceEnabled": bool(data.get("gdpr_compliance_enabled")) if data.get("gdpr_compliance_enabled") is not None else False,
                "showPoweredBy": bool(data.get("show_powered_by")) if data.get("show_powered_by") is not None else True,
                "privacyPolicyUrl": data.get("privacy_policy_url") or "",
                "passwordProtectionEnabled": bool(data.get("password_protection_enabled")) if data.get("password_protection_enabled") is not None else False,
                "passwordHash": data.get("password_hash") or "",
                # Geo restrictions
                "restrictedCountries": data.get("restricted_countries") or [],
                "allowedCountries": data.get("allowed_countries") or [],
                # Custom domain - booleans default to False
                "customDomain": data.get("custom_domain") or "",
                "customDomainVerified": bool(data.get("custom_domain_verified")) if data.get("custom_domain_verified") is not None else False,
                "sslVerified": bool(data.get("ssl_verified")) if data.get("ssl_verified") is not None else False,
                # Submit button, styles
                "submitButton": data.get("submit_button"),
                "titleStyle": data.get("title_style"),
                "subtitleStyle": data.get("subtitle_style"),
                # Full page layout - booleans default to False
                "fullPageProgressEnabled": bool(data.get("full_page_progress_enabled")) if data.get("full_page_progress_enabled") is not None else False,
                "fullPageKeyboardHintsEnabled": bool(data.get("full_page_keyboard_hints_enabled")) if data.get("full_page_keyboard_hints_enabled") is not None else False,
                # Metadata
                "idempotencyKey": data.get("idempotency_key"),
                "createdAt": data.get("created_at"),
                "updatedAt": data.get("updated_at"),
            }
            return normalize_booleans(form_data)
        return None
    
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
    async def decrement_user_forms_count(session: AsyncSession, user_id: str) -> None:
        """Decrement the user's forms count (never below zero)"""
        query = text("""
            UPDATE users 
            SET forms_count = GREATEST(forms_count - 1, 0)
            WHERE uid = :user_id
        """)
        await session.execute(query, {"user_id": user_id})

    @staticmethod
    async def delete_form(session: AsyncSession, form_id: str, user_id: str) -> bool:
        """Delete a form owned by user_id and permanently remove all related data from Neon DB. Returns True if deleted."""
        # Verify exists and ownership
        existing = await AsyncFormsService.get_form_by_id(session, form_id, user_id)
        if not existing:
            return False
        # Delete the form and all related data in a single transaction
        try:
            # Delete from all related tables to ensure complete cleanup
            # Even if FK constraints exist, explicit deletion ensures no orphaned data
            
            # Delete session recordings metadata
            await session.execute(text(
                "DELETE FROM sessions WHERE form_id = :form_id"
            ), {"form_id": form_id})
            
            # Delete session chunks/events
            await session.execute(text(
                "DELETE FROM form_sessions WHERE form_id = :form_id"
            ), {"form_id": form_id})
            
            # Delete form abandonment records
            await session.execute(text(
                "DELETE FROM form_abandons WHERE form_id = :form_id"
            ), {"form_id": form_id})
            
            # Delete submissions
            await session.execute(text(
                "DELETE FROM submissions WHERE form_id = :form_id"
            ), {"form_id": form_id})
            
            # Delete analytics events
            await session.execute(text(
                "DELETE FROM analytics WHERE form_id = :form_id"
            ), {"form_id": form_id})
            
            # Delete form versions
            await session.execute(text(
                "DELETE FROM form_versions WHERE form_id = :form_id"
            ), {"form_id": form_id})
            
            # Finally delete the form itself
            res = await session.execute(text(
                """
                DELETE FROM forms 
                WHERE id = :form_id AND user_id = :user_id
                RETURNING id
                """
            ), {"form_id": form_id, "user_id": user_id})
            row = res.mappings().first()
            if not row:
                await session.rollback()
                return False
            
            # Decrement user's forms count
            await AsyncFormsService.decrement_user_forms_count(session, user_id)
            await session.commit()
            return True
        except Exception:
            try:
                await session.rollback()
            except Exception:
                pass
            return False
    
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
        # Generate UUID for the form (handle missing or null/empty id)
        if not form_data.get('id'):
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
        json_fields = [
            'fields', 'theme', 'branding', 'allowed_domains',
            'redirect', 'restricted_countries', 'allowed_countries',
            'submit_button', 'title_style', 'subtitle_style'
        ]
        for json_field in json_fields:
            if json_field in validated_data and not isinstance(validated_data[json_field], str):
                validated_data[json_field] = json.dumps(validated_data[json_field])

        # Idempotency: if a key is provided, acquire an advisory transaction lock and check for an existing row
        ikey = validated_data.get('idempotency_key')
        if ikey:
            try:
                # Serialize concurrent creates with the same idempotency key
                await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": str(ikey)})
                # Return existing row when present (no duplicate insert)
                existing = await session.execute(
                    text("""
                        SELECT * FROM forms
                        WHERE idempotency_key = :k AND user_id = :uid
                        LIMIT 1
                    """),
                    {"k": str(ikey), "uid": str(user_id)}
                )
                row = existing.mappings().first()
                if row:
                    # Release the lock early by rolling back this read-only txn (no writes yet)
                    try:
                        await session.rollback()
                    except Exception:
                        pass
                    return dict(row)
            except Exception:
                # On lock/lookup issues, fall through to normal insert
                pass
        
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
        
        # Update user's forms count only on successful insert
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
        
        # Save current version before updating
        try:
            import uuid
            # Get the next version number
            version_query = text("""
                SELECT COALESCE(MAX(version_number), 0) + 1 as next_version
                FROM form_versions
                WHERE form_id = :form_id
            """)
            version_result = await session.execute(version_query, {"form_id": form_id})
            next_version = version_result.scalar() or 1
            
            # Save the current form state as a version
            version_id = str(uuid.uuid4())
            version_data = {
                k: v for k, v in existing_form.items() 
                if k not in ['id', 'user_id', 'created_at', 'updated_at', 'views', 'submissions']
            }
            
            save_version_query = text("""
                INSERT INTO form_versions (id, form_id, version_number, data, created_at)
                VALUES (:id, :form_id, :version_number, :data, NOW())
            """)
            await session.execute(save_version_query, {
                "id": version_id,
                "form_id": form_id,
                "version_number": next_version,
                "data": json.dumps(version_data)
            })
        except Exception as e:
            # Don't fail the update if version saving fails
            print(f"Version saving error: {e}")
            
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
        json_fields = [
            'fields', 'theme', 'branding', 'allowed_domains',
            'redirect', 'restricted_countries', 'allowed_countries',
            'submit_button', 'title_style', 'subtitle_style'
        ]
        for json_field in json_fields:
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