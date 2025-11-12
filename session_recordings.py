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

from .auth import get_current_user_uid
from .db.database import get_db_connection


# R2 Configuration (Cloudflare R2)
import os
R2_ENDPOINT_URL = os.getenv("R2_ENDPOINT_URL", "https://your-account-id.r2.cloudflarestorage.com")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "your-r2-access-key")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "your-r2-secret-key")
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "cleanenroll-session-recordings")

# Initialize R2 client
r2_client = boto3.client(
    's3',
    endpoint_url=R2_ENDPOINT_URL,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    region_name='auto'
)

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
    try:
        # Generate unique ID for the recording
        recording_id = str(uuid.uuid4())
        
        # Get form owner UID from database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get form owner
        cursor.execute(
            "SELECT user_id FROM forms WHERE id = %s",
            (recording_data.formId,)
        )
        form_result = cursor.fetchone()
        
        if not form_result:
            raise HTTPException(status_code=404, detail="Form not found")
        
        owner_uid = form_result[0]
        
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
        r2_client.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=r2_key,
            Body=json.dumps(recording_payload),
            ContentType='application/json'
        )
        
        # Store metadata in database
        cursor.execute("""
            INSERT INTO session_recordings 
            (id, form_id, owner_uid, start_time, end_time, user_agent, viewport_width, viewport_height, r2_key, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            recording_id,
            recording_data.formId,
            owner_uid,
            datetime.fromtimestamp(recording_data.startTime / 1000, timezone.utc),
            datetime.fromtimestamp(recording_data.endTime / 1000, timezone.utc) if recording_data.endTime else None,
            recording_data.userAgent,
            recording_data.viewport.get('width'),
            recording_data.viewport.get('height'),
            r2_key,
            datetime.now(timezone.utc)
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"success": True, "recordingId": recording_id}
        
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"R2 storage error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store recording: {str(e)}")


@router.get("/api/session-recordings")
async def get_session_recordings(
    form_id: Optional[str] = None,
    user_uid: str = Depends(get_current_user_uid)
):
    """Get session recordings for a specific owner UID, optionally filtered by form."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build query based on filters
        if form_id:
            cursor.execute("""
                SELECT id, form_id, start_time, end_time, user_agent, 
                       viewport_width, viewport_height, r2_key, created_at
                FROM session_recordings 
                WHERE owner_uid = %s AND form_id = %s
                ORDER BY created_at DESC
            """, (user_uid, form_id))
        else:
            cursor.execute("""
                SELECT id, form_id, start_time, end_time, user_agent, 
                       viewport_width, viewport_height, r2_key, created_at
                FROM session_recordings 
                WHERE owner_uid = %s
                ORDER BY created_at DESC
            """, (user_uid,))
        
        recordings = []
        for row in cursor.fetchall():
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
        
        cursor.close()
        conn.close()
        
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
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get recording metadata and verify ownership
        cursor.execute("""
            SELECT r2_key FROM session_recordings 
            WHERE id = %s AND owner_uid = %s
        """, (recording_id, user_uid))
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Recording not found")
        
        r2_key = result[0]
        
        # Fetch from R2
        response = r2_client.get_object(Bucket=R2_BUCKET_NAME, Key=r2_key)
        recording_data = json.loads(response['Body'].read())
        
        cursor.close()
        conn.close()
        
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
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get recording metadata and verify ownership
        cursor.execute("""
            SELECT r2_key FROM session_recordings 
            WHERE id = %s AND owner_uid = %s
        """, (recording_id, user_uid))
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Recording not found")
        
        r2_key = result[0]
        
        # Delete from R2
        r2_client.delete_object(Bucket=R2_BUCKET_NAME, Key=r2_key)
        
        # Delete from database
        cursor.execute("""
            DELETE FROM session_recordings 
            WHERE id = %s AND owner_uid = %s
        """, (recording_id, user_uid))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"success": True}
        
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"R2 deletion error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete recording: {str(e)}")
