"""
Zoom Integration API
User-level OAuth 2.0 flow and meeting creation via Zoom API
"""
from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import os
import requests
import logging
import json

logger = logging.getLogger("backend.zoom")

try:
    from db.database import async_session_maker  # type: ignore
except Exception:
    from ..db.database import async_session_maker  # type: ignore

router = APIRouter()

# Zoom User-level OAuth credentials from environment
ZOOM_CLIENT_ID = os.getenv("ZOOM_CLIENT_ID", "")
ZOOM_CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET", "")
ZOOM_REDIRECT_URI = os.getenv("ZOOM_REDIRECT_URI", "https://api.cleanenroll.com/api/zoom/callback")
FRONTEND_REDIRECT_URL = os.getenv("FRONTEND_REDIRECT_URL", "https://cleanenroll.com/dashboard?integrations=zoom&status=connected")

# Zoom OAuth endpoints
ZOOM_OAUTH_AUTHORIZE = "https://zoom.us/oauth/authorize"
ZOOM_OAUTH_TOKEN = "https://zoom.us/oauth/token"
ZOOM_API_BASE = "https://api.zoom.us/v2"

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


async def _get_user_zoom_token(user_id: str) -> str:
    """
    Get valid Zoom access token for a user, refreshing if necessary
    """
    async with async_session_maker() as session:
        result = await session.execute(
            text("SELECT access_token, refresh_token, expires_at FROM zoom_integrations WHERE uid = :uid"),
            {"uid": user_id}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=400, detail="Zoom not connected. Please connect your Zoom account first.")
        
        access_token, refresh_token, expires_at = row
        
        # Check if token is expired or about to expire (within 5 minutes)
        if expires_at and datetime.utcnow() >= expires_at - timedelta(minutes=5):
            # Refresh the token
            if not refresh_token:
                raise HTTPException(status_code=400, detail="Zoom token expired. Please reconnect.")
            
            try:
                token_response = requests.post(
                    ZOOM_OAUTH_TOKEN,
                    params={"grant_type": "refresh_token", "refresh_token": refresh_token},
                    auth=(ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET),
                    timeout=20
                )
                
                if token_response.status_code != 200:
                    logger.error(f"Zoom token refresh failed: {token_response.text}")
                    raise HTTPException(status_code=400, detail="Failed to refresh Zoom token. Please reconnect.")
                
                token_data = token_response.json()
                new_access_token = token_data.get("access_token")
                new_refresh_token = token_data.get("refresh_token", refresh_token)
                expires_in = token_data.get("expires_in", 3600)
                new_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
                
                # Update tokens in database
                await session.execute(
                    text("""UPDATE zoom_integrations 
                            SET access_token = :access_token, 
                                refresh_token = :refresh_token, 
                                expires_at = :expires_at,
                                updated_at = NOW()
                            WHERE uid = :uid"""),
                    {
                        "uid": user_id,
                        "access_token": new_access_token,
                        "refresh_token": new_refresh_token,
                        "expires_at": new_expires_at
                    }
                )
                await session.commit()
                return new_access_token
            
            except requests.RequestException as e:
                logger.exception(f"Zoom token refresh error: {e}")
                raise HTTPException(status_code=500, detail="Failed to refresh Zoom token")
        
        return access_token


@router.get("/api/zoom/authorize")
def zoom_authorize(userId: str = Query(...), redirect: Optional[str] = Query(None)):
    """
    Initiate Zoom OAuth authorization flow
    Redirects user to Zoom login page
    """
    if not ZOOM_CLIENT_ID or not ZOOM_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Zoom integration not configured")
    
    # Build state parameter to pass userId and redirect URL
    state = json.dumps({"userId": userId, "redirect": redirect or FRONTEND_REDIRECT_URL})
    
    # Zoom OAuth URL with required scopes
    auth_url = f"{ZOOM_OAUTH_AUTHORIZE}?response_type=code&client_id={ZOOM_CLIENT_ID}&redirect_uri={ZOOM_REDIRECT_URI}&state={state}"
    
    logger.info(f"Zoom OAuth initiated for user {userId}")
    return {"authorize_url": auth_url}


@router.get("/api/zoom/callback")
async def zoom_callback(code: str = Query(None), state: str = Query("{}")):
    """
    Handle Zoom OAuth callback
    Exchange authorization code for access token and store in database
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")
    
    # Parse state parameter
    try:
        parsed_state = json.loads(state)
    except Exception:
        parsed_state = {}
    
    user_id = parsed_state.get("userId")
    redirect_target = parsed_state.get("redirect") or FRONTEND_REDIRECT_URL
    
    if not user_id:
        logger.error(f"Zoom callback failed: Missing userId in state. Parsed state: {parsed_state}")
        raise HTTPException(status_code=400, detail="Missing userId in state")
    
    # Exchange code for access token
    try:
        token_response = requests.post(
            ZOOM_OAUTH_TOKEN,
            params={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": ZOOM_REDIRECT_URI
            },
            auth=(ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET),
            timeout=20
        )
        
        if token_response.status_code != 200:
            logger.error(f"Zoom token exchange failed: {token_response.text}")
            raise HTTPException(status_code=400, detail=f"OAuth exchange failed: {token_response.text}")
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)
        
        if not access_token:
            logger.error(f"Zoom OAuth response missing access_token: {token_data}")
            raise HTTPException(status_code=400, detail="OAuth exchange missing access_token")
        
        # Get user info from Zoom
        user_info_response = requests.get(
            f"{ZOOM_API_BASE}/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=20
        )
        
        zoom_user_id = None
        zoom_email = None
        if user_info_response.status_code == 200:
            user_info = user_info_response.json()
            zoom_user_id = user_info.get("id")
            zoom_email = user_info.get("email")
        
        # Store tokens in database
        async with async_session_maker() as session:
            await session.execute(
                text("""
                    INSERT INTO zoom_integrations 
                    (uid, access_token, refresh_token, expires_at, zoom_user_id, zoom_email, connected_at, updated_at)
                    VALUES (:uid, :access_token, :refresh_token, :expires_at, :zoom_user_id, :zoom_email, NOW(), NOW())
                    ON CONFLICT (uid) DO UPDATE SET
                        access_token = EXCLUDED.access_token,
                        refresh_token = EXCLUDED.refresh_token,
                        expires_at = EXCLUDED.expires_at,
                        zoom_user_id = EXCLUDED.zoom_user_id,
                        zoom_email = EXCLUDED.zoom_email,
                        updated_at = NOW()
                """),
                {
                    "uid": user_id,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_at": datetime.utcnow() + timedelta(seconds=expires_in),
                    "zoom_user_id": zoom_user_id,
                    "zoom_email": zoom_email
                }
            )
            await session.commit()
        
        logger.info(f"Zoom OAuth completed for user {user_id}")
        return RedirectResponse(url=redirect_target, status_code=302)
    
    except requests.RequestException as e:
        logger.exception(f"Zoom OAuth error: {e}")
        raise HTTPException(status_code=500, detail="Failed to complete Zoom OAuth")


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
    Create a Zoom meeting using user's OAuth token
    Body: { topic, start_time (ISO 8601), duration (minutes), agenda, timezone }
    Returns meeting details including join_url
    """
    user_id = _verify_firebase_uid(request)
    payload = await request.json()
    
    # Get user's Zoom access token (will refresh if needed)
    access_token = await _get_user_zoom_token(user_id)
    
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


# Helper function for auto-creating meetings during form submission
async def create_meeting_for_submission(user_id: str, meeting_details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Helper function to auto-create Zoom meeting when form is submitted
    Called from builder.py when a Zoom meeting field is detected
    
    Args:
        user_id: Form owner's Firebase UID
        meeting_details: { topic, start_time, duration, timezone, agenda }
    
    Returns:
        Meeting info dict or None if user hasn't connected Zoom
    """
    try:
        # Get user's Zoom access token
        access_token = await _get_user_zoom_token(user_id)
        
        # Prepare meeting data
        meeting_data = {
            "topic": meeting_details.get("topic", "Form Submission Meeting"),
            "type": 2,  # Scheduled meeting
            "start_time": meeting_details.get("start_time"),  # ISO 8601 format
            "duration": int(meeting_details.get("duration", 30)),
            "timezone": meeting_details.get("timezone", "UTC"),
            "agenda": meeting_details.get("agenda", ""),
            "settings": {
                "host_video": True,
                "participant_video": True,
                "join_before_host": False,
                "mute_upon_entry": True,
                "waiting_room": True,
                "audio": "both"
            }
        }
        
        # Create meeting via Zoom API
        response = requests.post(
            f"{ZOOM_API_BASE}/users/me/meetings",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            },
            json=meeting_data,
            timeout=20
        )
        
        if response.status_code != 201:
            logger.error(f"Zoom meeting auto-creation failed: {response.text}")
            return None
        
        meeting = response.json()
        
        return {
            "id": meeting.get("id"),
            "topic": meeting.get("topic"),
            "join_url": meeting.get("join_url"),
            "start_url": meeting.get("start_url"),
            "start_time": meeting.get("start_time"),
            "duration": meeting.get("duration"),
            "password": meeting.get("password")
        }
    
    except HTTPException:
        # User hasn't connected Zoom or token expired
        logger.warning(f"Cannot create Zoom meeting for user {user_id}: Zoom not connected")
        return None
    except Exception as e:
        logger.exception(f"Error auto-creating Zoom meeting: {e}")
        return None
