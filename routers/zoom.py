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

# Zoom OAuth credentials from environment
ZOOM_CLIENT_ID = os.getenv("ZOOM_CLIENT_ID", "")
ZOOM_CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET", "")
ZOOM_REDIRECT_URI = os.getenv("ZOOM_REDIRECT_URI", "http://localhost:8000/api/zoom/callback")

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


@router.get("/api/zoom/connect")
async def zoom_connect(request: Request):
    """
    Start Zoom OAuth flow
    Redirects user to Zoom authorization page
    """
    if not ZOOM_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Zoom integration not configured")
    
    # Verify user authentication
    user_id = _verify_firebase_uid(request)
    
    # Build Zoom OAuth URL
    auth_url = (
        f"https://zoom.us/oauth/authorize"
        f"?response_type=code"
        f"&client_id={ZOOM_CLIENT_ID}"
        f"&redirect_uri={ZOOM_REDIRECT_URI}"
        f"&state={user_id}"  # Pass user_id in state for callback
    )
    
    return {"authUrl": auth_url}


@router.get("/api/zoom/callback")
async def zoom_callback(code: str = Query(...), state: str = Query(...)):
    """
    Zoom OAuth callback
    Exchanges code for access token and stores in database
    """
    if not ZOOM_CLIENT_ID or not ZOOM_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Zoom integration not configured")
    
    user_id = state  # User ID passed in state parameter
    
    try:
        # Exchange authorization code for access token
        token_response = requests.post(
            "https://zoom.us/oauth/token",
            auth=(ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": ZOOM_REDIRECT_URI
            },
            timeout=20
        )
        
        if token_response.status_code != 200:
            logger.error(f"Zoom token exchange failed: {token_response.text}")
            raise HTTPException(status_code=400, detail="Failed to connect to Zoom")
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        # Get Zoom user info
        user_response = requests.get(
            "https://api.zoom.us/v2/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=20
        )
        
        zoom_user_id = None
        zoom_email = None
        if user_response.status_code == 200:
            user_data = user_response.json()
            zoom_user_id = user_data.get("id")
            zoom_email = user_data.get("email")
        
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
                    "expires_at": expires_at,
                    "zoom_user_id": zoom_user_id,
                    "zoom_email": zoom_email
                }
            )
            await session.commit()
        
        # Redirect back to dashboard integrations page
        return RedirectResponse(url="/dashboard?tab=integrations&zoom=connected")
    
    except Exception as e:
        logger.exception(f"Zoom OAuth callback error: {e}")
        raise HTTPException(status_code=500, detail="Failed to complete Zoom connection")


@router.get("/api/zoom/status")
async def zoom_status(request: Request):
    """
    Check if user has connected Zoom account
    Returns connection status and user info
    """
    user_id = _verify_firebase_uid(request)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""
                SELECT zoom_email, connected_at, expires_at
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
            "email": row[0],
            "connectedAt": row[1].isoformat() if row[1] else None,
            "expiresAt": row[2].isoformat() if row[2] else None
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
    Create a Zoom meeting
    Body: { topic, start_time (ISO 8601), duration (minutes), agenda, timezone }
    Returns meeting details including join_url
    """
    user_id = _verify_firebase_uid(request)
    payload = await request.json()
    
    # Get user's Zoom access token
    async with async_session_maker() as session:
        result = await session.execute(
            text("""
                SELECT access_token, refresh_token, expires_at
                FROM zoom_integrations
                WHERE uid = :uid
            """),
            {"uid": user_id}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=400, detail="Zoom not connected. Please connect your Zoom account first.")
        
        access_token = row[0]
        # TODO: Add token refresh logic if expired
    
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
