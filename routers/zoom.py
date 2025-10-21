"""
Zoom Integration API
OAuth 2.0 flow and meeting creation via Zoom API
"""
from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from datetime import datetime, timedelta
import os
import requests
import logging

logger = logging.getLogger("backend.zoom")

try:
    from db.database import async_session_maker  # type: ignore
except Exception:
    from ..db.database import async_session_maker  # type: ignore

router = APIRouter()

# Zoom Server-to-Server OAuth credentials from environment
ZOOM_CLIENT_ID = os.getenv("ZOOM_CLIENT_ID", "")
ZOOM_CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET", "")
ZOOM_ACCOUNT_ID = os.getenv("ZOOM_ACCOUNT_ID", "")

def _verify_firebase_uid(request: Request) -> str:
    """Extract and verify Firebase UID from Authorization header."""
    try:
        from firebase_admin import auth as _admin_auth  # type: ignore
    except Exception:
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
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


async def _get_zoom_access_token() -> str:
    """
    Get Server-to-Server OAuth access token from Zoom
    No redirect URI or user authorization needed
    """
    if not ZOOM_CLIENT_ID or not ZOOM_CLIENT_SECRET or not ZOOM_ACCOUNT_ID:
        raise HTTPException(status_code=500, detail="Zoom integration not configured")
    
    try:
        token_response = requests.post(
            "https://zoom.us/oauth/token",
            params={
                "grant_type": "account_credentials",
                "account_id": ZOOM_ACCOUNT_ID
            },
            auth=(ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET),
            timeout=20
        )
        
        if token_response.status_code != 200:
            logger.error(f"Zoom Server-to-Server token failed: {token_response.text}")
            raise HTTPException(status_code=500, detail="Failed to authenticate with Zoom")
        
        token_data = token_response.json()
        return token_data.get("access_token")
    
    except requests.RequestException as e:
        logger.exception(f"Zoom token request error: {e}")
        raise HTTPException(status_code=500, detail="Failed to authenticate with Zoom")


@router.post("/api/zoom/connect")
async def zoom_connect(request: Request):
    """
    Enable Zoom integration for user (Server-to-Server OAuth)
    No redirect flow needed - direct authentication
    """
    # Verify user authentication
    user_id = _verify_firebase_uid(request)
    
    # Test the Server-to-Server OAuth credentials
    try:
        access_token = await _get_zoom_access_token()
        
        # Store connection status in database
        async with async_session_maker() as session:
            await session.execute(
                text("""
                    INSERT INTO zoom_integrations 
                    (uid, access_token, expires_at, connected_at, updated_at)
                    VALUES (:uid, :access_token, :expires_at, NOW(), NOW())
                    ON CONFLICT (uid) DO UPDATE SET
                        access_token = EXCLUDED.access_token,
                        expires_at = EXCLUDED.expires_at,
                        updated_at = NOW()
                """),
                {
                    "uid": user_id,
                    "access_token": access_token,
                    "expires_at": datetime.utcnow() + timedelta(hours=1)
                }
            )
            await session.commit()
        
        return {"success": True, "message": "Zoom integration enabled"}
    
    except Exception as e:
        logger.exception(f"Zoom connect error: {e}")
        raise HTTPException(status_code=500, detail="Failed to enable Zoom integration")


@router.get("/api/zoom/status")
async def zoom_status(request: Request):
    """
    Check if Zoom integration is enabled
    Returns connection status
    """
    user_id = _verify_firebase_uid(request)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""
                SELECT connected_at
                FROM zoom_integrations
                WHERE uid = :uid
            """),
            {"uid": user_id}
        )
        row = result.fetchone()
        
        if not row:
            return {"connected": False}
        
        return {
            "connected": True,
            "connectedAt": row[0].isoformat() if row[0] else None
        }


@router.post("/api/zoom/disconnect")
async def zoom_disconnect(request: Request):
    """
    Disconnect Zoom integration
    Removes stored tokens from database
    """
    user_id = _verify_firebase_uid(request)
    
    async with async_session_maker() as session:
        await session.execute(
            text("DELETE FROM zoom_integrations WHERE uid = :uid"),
            {"uid": user_id}
        )
        await session.commit()
    
    return {"success": True, "message": "Zoom integration disconnected"}


@router.post("/api/zoom/create-meeting")
async def create_zoom_meeting(request: Request):
    """
    Create a Zoom meeting using Server-to-Server OAuth
    Body: { topic, start_time (ISO 8601), duration (minutes), agenda, timezone }
    Returns meeting details including join_url
    """
    user_id = _verify_firebase_uid(request)
    payload = await request.json()
    
    # Check if user has enabled Zoom integration
    async with async_session_maker() as session:
        result = await session.execute(
            text("SELECT 1 FROM zoom_integrations WHERE uid = :uid"),
            {"uid": user_id}
        )
        if not result.fetchone():
            raise HTTPException(status_code=400, detail="Zoom not enabled. Please enable Zoom integration first.")
    
    # Get fresh Server-to-Server OAuth token
    access_token = await _get_zoom_access_token()
    
    # Create Zoom meeting via API
    meeting_data = {
        "topic": payload.get("topic", "Meeting"),
        "type": 2,  # Scheduled meeting
        "start_time": payload.get("start_time"),  # ISO 8601 format
        "duration": int(payload.get("duration", 30)),
        "timezone": payload.get("timezone", "UTC"),
        "agenda": payload.get("agenda", ""),
        "settings": {
            "host_video": True,
            "participant_video": True,
            "join_before_host": False,
            "mute_upon_entry": True,
            "waiting_room": True,
            "audio": "both"
        }
    }
    
    try:
        response = requests.post(
            "https://api.zoom.us/v2/users/me/meetings",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            },
            json=meeting_data,
            timeout=20
        )
        
        if response.status_code != 201:
            logger.error(f"Zoom meeting creation failed: {response.text}")
            raise HTTPException(status_code=400, detail="Failed to create Zoom meeting")
        
        meeting = response.json()
        
        return {
            "success": True,
            "meeting": {
                "id": meeting.get("id"),
                "topic": meeting.get("topic"),
                "join_url": meeting.get("join_url"),
                "start_url": meeting.get("start_url"),
                "start_time": meeting.get("start_time"),
                "duration": meeting.get("duration"),
                "password": meeting.get("password")
            }
        }
    
    except requests.RequestException as e:
        logger.exception(f"Zoom API request error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create Zoom meeting")
