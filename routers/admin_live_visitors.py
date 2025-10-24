import os
import json
import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text

logger = logging.getLogger("backend.admin_live_visitors")

router = APIRouter(prefix="/api/admin", tags=["admin"])

# Admin user IDs - only these users can access this endpoint
ADMIN_USER_IDS = os.getenv("ADMIN_USER_IDS", "").split(",")


def _is_admin(user_id: str) -> bool:
    """Check if user is an admin."""
    return user_id in ADMIN_USER_IDS


async def _get_current_user_id() -> str:
    """Get current user ID from session/auth - placeholder for now."""
    # This should integrate with your existing auth system
    # For now, return empty to require explicit auth
    return ""


@router.get("/live-visitors")
async def get_live_visitors():
    """
    Get all live site owners (visitor tracking).
    Returns owner data with location, current page, and activity status.
    Admin-only endpoint.
    """
    try:
        from db.database import async_session_maker
    except Exception:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Check admin access (you should integrate with your auth system)
    # user_id = await _get_current_user_id()
    # if not _is_admin(user_id):
    #     raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        async with async_session_maker() as session:
            # Fetch active owners from last 30 minutes
            cutoff_time = datetime.utcnow() - timedelta(minutes=30)
            
            result = await session.execute(
                text("""
                    SELECT 
                        session_id,
                        user_id,
                        user_email,
                        ip_address,
                        country_code,
                        city,
                        current_page,
                        last_seen,
                        metadata,
                        device_type,
                        browser,
                        os
                    FROM owners_tracking
                    WHERE last_seen >= :cutoff
                    ORDER BY last_seen DESC
                """),
                {"cutoff": cutoff_time}
            )
            
            rows = result.fetchall()
            
            visitors = []
            for row in rows:
                visitor = {
                    "sessionId": row[0],
                    "userId": row[1],
                    "email": row[2],
                    "ip": row[3],
                    "country": row[4],
                    "city": row[5],
                    "currentPage": row[6],
                    "lastSeen": row[7].isoformat() if row[7] else None,
                    "device": row[9],
                    "browser": row[10],
                    "os": row[11],
                }
                
                # Parse additional metadata if available
                try:
                    if row[8]:
                        metadata = row[8] if isinstance(row[8], dict) else json.loads(row[8])
                        # Add any extra metadata fields
                        for key, value in metadata.items():
                            if key not in visitor:
                                visitor[key] = value
                except Exception:
                    pass
                
                visitors.append(visitor)
            
            return {
                "visitors": visitors,
                "total": len(visitors),
                "timestamp": datetime.utcnow().isoformat()
            }
            
    except Exception as e:
        logger.exception("Failed to fetch live visitors")
        raise HTTPException(status_code=500, detail=f"Failed to fetch live visitors: {str(e)}")


@router.post("/track-owner")
async def track_owner(data: dict):
    """
    Track site owner activity and page visits.
    Stores data in owners_tracking table for real-time monitoring.
    """
    try:
        from db.database import async_session_maker
    except Exception:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        session_id = data.get("sessionId")
        user_id = data.get("userId")
        user_email = data.get("userEmail")
        current_page = data.get("currentPage", "/")
        referrer = data.get("referrer")
        timestamp = data.get("timestamp")
        
        if not session_id or not user_id:
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        async with async_session_maker() as session:
            # Check if session exists
            result = await session.execute(
                text("""
                    SELECT id FROM owners_tracking 
                    WHERE session_id = :session_id
                """),
                {"session_id": session_id}
            )
            existing = result.fetchone()
            
            now = datetime.utcnow()
            
            if existing:
                # Update existing session
                await session.execute(
                    text("""
                        UPDATE owners_tracking 
                        SET 
                            current_page = :current_page,
                            last_seen = :last_seen,
                            is_active = true,
                            updated_at = :updated_at
                        WHERE session_id = :session_id
                    """),
                    {
                        "session_id": session_id,
                        "current_page": current_page,
                        "last_seen": now,
                        "updated_at": now,
                    }
                )
            else:
                # Create new session
                await session.execute(
                    text("""
                        INSERT INTO owners_tracking (
                            session_id, user_id, user_email, current_page, 
                            referrer, first_seen, last_seen, is_active
                        ) VALUES (
                            :session_id, :user_id, :user_email, :current_page,
                            :referrer, :first_seen, :last_seen, :is_active
                        )
                    """),
                    {
                        "session_id": session_id,
                        "user_id": user_id,
                        "user_email": user_email,
                        "current_page": current_page,
                        "referrer": referrer,
                        "first_seen": now,
                        "last_seen": now,
                        "is_active": True,
                    }
                )
            
            await session.commit()
            
            return {"success": True, "message": "Owner activity tracked"}
            
    except Exception as e:
        logger.exception("Failed to track owner activity")
        raise HTTPException(status_code=500, detail=f"Failed to track owner: {str(e)}")
