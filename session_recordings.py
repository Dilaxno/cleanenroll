"""
Session recordings API endpoints for storing and retrieving rrweb recordings.
Handles R2 storage and retrieval of session data by owner UID.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field

try:
    from .db.database import async_session_maker
except ImportError:
    # Fallback for flat directory structure
    from db.database import async_session_maker

from sqlalchemy import text

# Firebase authentication
import firebase_admin
from firebase_admin import auth as firebase_auth
from fastapi import Header

async def get_current_user_uid(authorization: str = Header(None)) -> str:
    """Extract and verify Firebase token from Authorization header"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, 
            detail="Authorization header missing or invalid format"
        )
    
    token = authorization.split("Bearer ")[1]
    
    try:
        # Verify the Firebase token
        decoded_token = firebase_auth.verify_id_token(token)
        return decoded_token['uid']
    except Exception as e:
        raise HTTPException(
            status_code=401, 
            detail=f"Invalid token: {str(e)}"
        )


# Use the same R2 configuration as other uploads (backgrounds, images, etc.)
from routers.builder import _r2_client, R2_BUCKET

router = APIRouter()


class SessionRecordingData(BaseModel):
    events: List[Dict]
    startTime: int
    endTime: int
    formId: str
    userAgent: str
    viewport: Dict[str, int]


class SessionRecordingResponse(BaseModel):
    id: str
    formId: str
    startTime: int
    endTime: Optional[int]
    userAgent: str
    viewport: Dict[str, int]
    createdAt: str
    r2Key: str


@router.post("/api/session-recordings")
async def store_session_recording(
    recording_data: SessionRecordingData,
    request: Request
):
    """Store a session recording in R2 and metadata in database."""
    import logging
    logger = logging.getLogger("session_recordings")
    
    try:
        # Validate required fields
        if not recording_data.formId:
            logger.error("Missing formId in session recording request")
            raise HTTPException(status_code=400, detail="Missing formId")
        
        logger.info(f"Received session recording request for form_id: {recording_data.formId}")
        
        # Generate unique ID for the recording
        recording_id = str(uuid.uuid4())
        logger.info(f"Generated recording_id: {recording_id}")
        
        # Get form owner UID from database
        async with async_session_maker() as session:
            # Get form owner
            result = await session.execute(
                text("SELECT user_id FROM forms WHERE id = :form_id"),
                {"form_id": recording_data.formId}
            )
            form_result = result.fetchone()
            
            if not form_result:
                logger.error(f"Form not found: {recording_data.formId}")
                raise HTTPException(status_code=404, detail="Form not found")
            
            owner_uid = form_result[0]
            logger.info(f"Found form owner_uid: {owner_uid}")
        
        # Check recording limits for free users
        async with async_session_maker() as session:
            # Auto-reset counter if month has passed
            await session.execute(
                text("""
                    UPDATE users 
                    SET recordings_this_month = 0,
                        recording_limit_reset_date = DATE_TRUNC('month', CURRENT_TIMESTAMP) + INTERVAL '1 month'
                    WHERE uid = :uid 
                      AND recording_limit_reset_date <= CURRENT_TIMESTAMP
                """),
                {"uid": owner_uid}
            )
            await session.commit()
            
            # Get current usage and check limits
            result = await session.execute(
                text("""
                    SELECT recordings_this_month, recordings_limit, plan
                    FROM users
                    WHERE uid = :uid
                """),
                {"uid": owner_uid}
            )
            user_data = result.fetchone()
            
            if not user_data:
                logger.error(f"User not found: {owner_uid}")
                raise HTTPException(status_code=404, detail="User not found")
            
            recordings_used = int(user_data[0] or 0)
            recordings_limit = int(user_data[1] or 10)
            user_plan = user_data[2] or "free"
            
            # Check if user is on free plan and has exceeded limit
            is_pro = user_plan.lower() in ["pro", "business", "enterprise"]
            
            if not is_pro and recordings_used >= recordings_limit:
                logger.warning(f"Recording limit reached for user {owner_uid}: {recordings_used}/{recordings_limit}")
                raise HTTPException(
                    status_code=429,
                    detail=f"Monthly recording limit reached ({recordings_limit} recordings). Upgrade to Pro for 100 recordings per month."
                )
        
        # Create R2 key with owner UID for organization
        r2_key = f"recordings/{owner_uid}/{recording_data.formId}/{recording_id}.json"
        
        # Prepare recording data for storage
        recording_payload = {
            "id": recording_id,
            "formId": recording_data.formId,
            "events": recording_data.events,
            "startTime": recording_data.startTime,
            "endTime": recording_data.endTime,
            "userAgent": recording_data.userAgent,
            "viewport": recording_data.viewport,
            "createdAt": datetime.now(timezone.utc).isoformat()
        }
        
        # Store in R2
        logger.info(f"Storing recording in R2 with key: {r2_key}")
        s3 = _r2_client()
        s3.put_object(
            Bucket=R2_BUCKET,
            Key=r2_key,
            Body=json.dumps(recording_payload),
            ContentType='application/json'
        )
        logger.info("Successfully stored recording in R2")
        
        # Store metadata in database
        logger.info("Storing metadata in Neon DB")
        
        # Validate all required fields before database insertion
        if not recording_data.formId:
            raise HTTPException(status_code=400, detail="Missing formId")
        if not owner_uid:
            raise HTTPException(status_code=400, detail="Missing owner_uid")
        if not recording_id:
            raise HTTPException(status_code=400, detail="Missing recording_id")
            
        logger.info(f"Inserting recording with form_id: {recording_data.formId}, owner_uid: {owner_uid}")
        
        async with async_session_maker() as session:
            await session.execute(text("""
                INSERT INTO session_recordings 
                (id, form_id, owner_uid, start_time, end_time, user_agent, viewport_width, viewport_height, r2_key, created_at)
                VALUES (:recording_id, :form_id, :owner_uid, :start_time, :end_time, :user_agent, :viewport_width, :viewport_height, :r2_key, :created_at)
            """), {
                "recording_id": recording_id,
                "form_id": recording_data.formId,
                "owner_uid": owner_uid,
                "start_time": datetime.fromtimestamp(recording_data.startTime / 1000, timezone.utc),
                "end_time": datetime.fromtimestamp(recording_data.endTime / 1000, timezone.utc) if recording_data.endTime else None,
                "user_agent": recording_data.userAgent or "Unknown",
                "viewport_width": recording_data.viewport.get('width') if recording_data.viewport else None,
                "viewport_height": recording_data.viewport.get('height') if recording_data.viewport else None,
                "r2_key": r2_key,
                "created_at": datetime.now(timezone.utc)
            })
            await session.commit()
        logger.info(f"Successfully stored recording metadata in DB with ID: {recording_id}")
        
        # Increment recording counter for the user
        async with async_session_maker() as session:
            await session.execute(
                text("""
                    UPDATE users 
                    SET recordings_this_month = recordings_this_month + 1
                    WHERE uid = :uid
                """),
                {"uid": owner_uid}
            )
            await session.commit()
        logger.info(f"Incremented recording counter for user {owner_uid}")
        
        return {"success": True, "recordingId": recording_id}
        
    except ClientError as e:
        logger.error(f"R2 storage error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"R2 storage error: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to store recording: {str(e)}")
        logger.error(f"Recording data received: formId={getattr(recording_data, 'formId', 'MISSING')}, "
                    f"startTime={getattr(recording_data, 'startTime', 'MISSING')}, "
                    f"endTime={getattr(recording_data, 'endTime', 'MISSING')}")
        
        # Provide more specific error messages
        if "form_id" in str(e).lower() or "formid" in str(e).lower():
            raise HTTPException(status_code=400, detail="Invalid or missing formId parameter")
        elif "owner_uid" in str(e).lower():
            raise HTTPException(status_code=400, detail="Unable to determine form owner")
        else:
            raise HTTPException(status_code=500, detail=f"Failed to store recording: {str(e)}")


@router.get("/api/session-recordings/usage")
async def get_recording_usage(
    user_uid: str = Depends(get_current_user_uid)
):
    """Get the user's current monthly recording usage and limit.
    Response: { "used": int, "limit": int, "resetDate": str, "isPro": bool }
    """
    try:
        async with async_session_maker() as session:
            # Auto-reset counter if month has passed
            await session.execute(
                text("""
                    UPDATE users 
                    SET recordings_this_month = 0,
                        recording_limit_reset_date = DATE_TRUNC('month', CURRENT_TIMESTAMP) + INTERVAL '1 month'
                    WHERE uid = :uid 
                      AND recording_limit_reset_date <= CURRENT_TIMESTAMP
                """),
                {"uid": user_uid}
            )
            await session.commit()
            
            # Get current usage
            result = await session.execute(
                text("""
                    SELECT recordings_this_month, recordings_limit, recording_limit_reset_date, plan
                    FROM users
                    WHERE uid = :uid
                """),
                {"uid": user_uid}
            )
            row = result.fetchone()
            
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            
            used = int(row[0] or 0)
            limit = int(row[1] or 10)
            reset_date = row[2]
            user_plan = row[3] or "free"
            
            is_pro = user_plan.lower() in ["pro", "business", "enterprise"]
            
            # Pro users have 100 recordings limit
            if is_pro:
                limit = 100
            
            return {
                "used": used,
                "limit": limit,
                "resetDate": reset_date.isoformat() if reset_date else None,
                "isPro": is_pro
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get recording usage: {str(e)}")


@router.get("/api/session-recordings")
async def get_session_recordings(
    form_id: Optional[str] = None,
    user_uid: str = Depends(get_current_user_uid)
):
    """Get session recordings for a specific owner UID, optionally filtered by form."""
    try:
        async with async_session_maker() as session:
            # Build query based on filters
            if form_id:
                result = await session.execute(text("""
                    SELECT id, form_id, start_time, end_time, user_agent, 
                           viewport_width, viewport_height, r2_key, created_at
                    FROM session_recordings 
                    WHERE owner_uid = :user_uid AND form_id = :form_id
                    ORDER BY created_at DESC
                """), {"user_uid": user_uid, "form_id": form_id})
            else:
                result = await session.execute(text("""
                    SELECT id, form_id, start_time, end_time, user_agent, 
                           viewport_width, viewport_height, r2_key, created_at
                    FROM session_recordings 
                    WHERE owner_uid = :user_uid
                    ORDER BY created_at DESC
                """), {"user_uid": user_uid})
            
            rows = result.fetchall()
            recordings = []
            for row in rows:
                recordings.append({
                    "id": row[0],
                    "formId": row[1],
                    "startTime": int(row[2].timestamp() * 1000) if row[2] else None,
                    "endTime": int(row[3].timestamp() * 1000) if row[3] else None,
                    "userAgent": row[4],
                    "viewport": {
                        "width": row[5],
                        "height": row[6]
                    },
                    "r2Key": row[7],
                    "createdAt": row[8].isoformat() if row[8] else None
                })
        
        return {"recordings": recordings}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch recordings: {str(e)}")


@router.get("/api/session-recordings/{recording_id}")
async def get_session_recording_data(
    recording_id: str,
    user_uid: str = Depends(get_current_user_uid)
):
    """Get the full recording data from R2 for playback."""
    try:
        async with async_session_maker() as session:
            # Get recording metadata and verify ownership, also fetch form name
            result = await session.execute(
                text("""SELECT sr.r2_key, f.title, f.name 
                     FROM session_recordings sr
                     LEFT JOIN forms f ON sr.form_id = f.id
                     WHERE sr.id = :recording_id AND sr.owner_uid = :user_uid"""),
                {"recording_id": recording_id, "user_uid": user_uid}
            )
            
            row = result.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Recording not found")
            
            r2_key = row[0]
            form_title = row[1]
            form_name = row[2]
            # Use title if available, otherwise fall back to name
            form_display_name = form_title or form_name or "Unknown Form"
        
        # Fetch from R2
        s3 = _r2_client()
        response = s3.get_object(Bucket=R2_BUCKET, Key=r2_key)
        recording_data = json.loads(response['Body'].read())
        
        # Add form name to the response
        recording_data['formName'] = form_display_name
        
        return recording_data
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            raise HTTPException(status_code=404, detail="Recording data not found in storage")
        raise HTTPException(status_code=500, detail=f"R2 retrieval error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch recording data: {str(e)}")


@router.delete("/api/session-recordings/{recording_id}")
async def delete_session_recording(
    recording_id: str,
    user_uid: str = Depends(get_current_user_uid)
):
    """Delete a session recording from both R2 and database."""
    try:
        async with async_session_maker() as session:
            # Get recording metadata and verify ownership
            result = await session.execute(
                text("""SELECT r2_key FROM session_recordings 
                     WHERE id = :recording_id AND owner_uid = :user_uid"""),
                {"recording_id": recording_id, "user_uid": user_uid}
            )
            
            row = result.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Recording not found")
            
            r2_key = row[0]
        
        # Delete from R2
        s3 = _r2_client()
        s3.delete_object(Bucket=R2_BUCKET, Key=r2_key)
        
        # Delete from database
        async with async_session_maker() as session:
            await session.execute(
                text("""DELETE FROM session_recordings 
                     WHERE id = :recording_id AND owner_uid = :user_uid"""),
                {"recording_id": recording_id, "user_uid": user_uid}
            )
            await session.commit()
        
        return {"success": True}
        
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"R2 deletion error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete recording: {str(e)}")


class BatchDeleteRequest(BaseModel):
    recording_ids: List[str] = Field(..., description="List of recording IDs to delete")


@router.post("/api/session-recordings/batch-delete")
async def batch_delete_session_recordings(
    request: BatchDeleteRequest,
    user_uid: str = Depends(get_current_user_uid)
):
    """Delete multiple session recordings from both R2 and database."""
    if not request.recording_ids:
        raise HTTPException(status_code=400, detail="No recording IDs provided")
    
    deleted_count = 0
    failed_count = 0
    errors = []
    
    try:
        async with async_session_maker() as session:
            # Get all recording metadata and verify ownership
            placeholders = ",".join([f":id_{i}" for i in range(len(request.recording_ids))])
            params = {f"id_{i}": recording_id for i, recording_id in enumerate(request.recording_ids)}
            params["user_uid"] = user_uid
            
            result = await session.execute(
                text(f"""SELECT id, r2_key FROM session_recordings 
                     WHERE id IN ({placeholders}) AND owner_uid = :user_uid"""),
                params
            )
            
            recordings = result.fetchall()
            
            if not recordings:
                raise HTTPException(status_code=404, detail="No recordings found")
            
            # Delete from R2
            s3 = _r2_client()
            for row in recordings:
                recording_id = row[0]
                r2_key = row[1]
                try:
                    s3.delete_object(Bucket=R2_BUCKET, Key=r2_key)
                    deleted_count += 1
                except Exception as e:
                    failed_count += 1
                    errors.append(f"Failed to delete R2 object for {recording_id}: {str(e)}")
            
            # Delete from database (all at once)
            await session.execute(
                text(f"""DELETE FROM session_recordings 
                     WHERE id IN ({placeholders}) AND owner_uid = :user_uid"""),
                params
            )
            await session.commit()
        
        return {
            "success": True,
            "deleted_count": deleted_count,
            "failed_count": failed_count,
            "errors": errors if errors else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete recordings: {str(e)}")
