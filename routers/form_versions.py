"""
Form versions API router for managing form version history
"""
from fastapi import APIRouter, HTTPException, Request, Query
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import text
from db.database import async_session_maker
from slowapi import Limiter
from utils.limiter import forwarded_for_ip
import logging
import json

router = APIRouter(prefix="/api/builder/forms", tags=["form_versions"])
limiter = Limiter(key_func=forwarded_for_ip)
logger = logging.getLogger("backend.form_versions")

def _verify_firebase_uid(request: Request) -> str:
    """Extract and verify Firebase UID from Authorization header."""
    try:
        from firebase_admin import auth as _admin_auth  # type: ignore
    except Exception as e:
        logger.error(f"Firebase Admin import failed: {e}")
        raise HTTPException(status_code=500, detail="Firebase Admin not available on server")
    
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authz or not authz.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization token")
    
    token = authz.split(" ", 1)[1].strip()
    try:
        decoded = _admin_auth.verify_id_token(token)
        uid = decoded.get("uid")
        if not uid:
            raise HTTPException(status_code=401, detail="Invalid token")
        return uid
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firebase token verification failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")

@router.get("/{form_id}/versions")
@limiter.limit("120/minute")
async def get_form_versions(
    form_id: str,
    request: Request,
    limit: int = Query(50, le=200)
):
    """
    Get version history for a form.
    Returns list of versions with metadata.
    """
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    async with async_session_maker() as session:
        # Verify form ownership
        form_check = await session.execute(
            text("SELECT user_id FROM forms WHERE id = :fid LIMIT 1"),
            {"fid": form_id}
        )
        form_row = form_check.mappings().first()
        if not form_row or form_row.get("user_id") != uid:
            raise HTTPException(status_code=404, detail="Form not found")
        
        # Fetch versions
        query = text("""
            SELECT id, version_number, created_at
            FROM form_versions
            WHERE form_id = :form_id
            ORDER BY version_number DESC
            LIMIT :limit
        """)
        result = await session.execute(query, {"form_id": form_id, "limit": limit})
        rows = result.mappings().all()
        
        versions = []
        for row in rows:
            versions.append({
                "id": row.get("id"),
                "version_number": row.get("version_number"),
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None
            })
        
        return {"versions": versions}

@router.get("/{form_id}/versions/{version_id}")
@limiter.limit("120/minute")
async def get_form_version(
    form_id: str,
    version_id: str,
    request: Request
):
    """
    Get a specific version's full data.
    """
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    async with async_session_maker() as session:
        # Verify form ownership
        form_check = await session.execute(
            text("SELECT user_id FROM forms WHERE id = :fid LIMIT 1"),
            {"fid": form_id}
        )
        form_row = form_check.mappings().first()
        if not form_row or form_row.get("user_id") != uid:
            raise HTTPException(status_code=404, detail="Form not found")
        
        # Fetch version data
        query = text("""
            SELECT id, version_number, data, created_at
            FROM form_versions
            WHERE form_id = :form_id AND id = :version_id
            LIMIT 1
        """)
        result = await session.execute(query, {"form_id": form_id, "version_id": version_id})
        row = result.mappings().first()
        
        if not row:
            raise HTTPException(status_code=404, detail="Version not found")
        
        # Parse JSON data
        data = row.get("data")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                data = {}
        
        return {
            "id": row.get("id"),
            "version_number": row.get("version_number"),
            "data": data,
            "created_at": row.get("created_at").isoformat() if row.get("created_at") else None
        }

@router.post("/{form_id}/versions/{version_id}/restore")
@limiter.limit("30/minute")
async def restore_form_version(
    form_id: str,
    version_id: str,
    request: Request
):
    """
    Restore a form to a previous version.
    Creates a new version of the current state before restoring.
    """
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    async with async_session_maker() as session:
        # Verify form ownership
        form_check = await session.execute(
            text("SELECT user_id FROM forms WHERE id = :fid LIMIT 1"),
            {"fid": form_id}
        )
        form_row = form_check.mappings().first()
        if not form_row or form_row.get("user_id") != uid:
            raise HTTPException(status_code=404, detail="Form not found")
        
        # Fetch version data to restore
        version_query = text("""
            SELECT data
            FROM form_versions
            WHERE form_id = :form_id AND id = :version_id
            LIMIT 1
        """)
        version_result = await session.execute(version_query, {"form_id": form_id, "version_id": version_id})
        version_row = version_result.mappings().first()
        
        if not version_row:
            raise HTTPException(status_code=404, detail="Version not found")
        
        # Parse version data
        version_data = version_row.get("data")
        if isinstance(version_data, str):
            try:
                version_data = json.loads(version_data)
            except:
                raise HTTPException(status_code=400, detail="Invalid version data")
        
        if not isinstance(version_data, dict):
            raise HTTPException(status_code=400, detail="Invalid version data format")
        
        # Build UPDATE query dynamically from version data
        # Filter out fields that shouldn't be restored
        excluded_fields = {'id', 'user_id', 'created_at', 'views', 'submissions'}
        fields_to_update = {k: v for k, v in version_data.items() if k not in excluded_fields}
        
        if not fields_to_update:
            raise HTTPException(status_code=400, detail="No fields to restore")
        
        # Convert complex fields to JSON strings if needed
        for field in ['fields', 'theme', 'branding', 'allowed_domains']:
            if field in fields_to_update and not isinstance(fields_to_update[field], str):
                fields_to_update[field] = json.dumps(fields_to_update[field])
        
        # Add updated_at timestamp
        fields_to_update['updated_at'] = datetime.now()
        
        # Build SET clause
        set_clause = ', '.join(f"{key} = :{key}" for key in fields_to_update.keys())
        
        # Execute update
        update_query = text(f"""
            UPDATE forms
            SET {set_clause}
            WHERE id = :form_id AND user_id = :user_id
            RETURNING id
        """)
        
        params = {**fields_to_update, 'form_id': form_id, 'user_id': uid}
        update_result = await session.execute(update_query, params)
        await session.commit()
        
        updated = update_result.mappings().first()
        if not updated:
            raise HTTPException(status_code=500, detail="Failed to restore version")
        
        return {
            "success": True,
            "message": "Form restored to previous version",
            "form_id": form_id
        }
