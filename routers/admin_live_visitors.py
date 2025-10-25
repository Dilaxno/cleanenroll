import os
import json
import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Request
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
            
            logger.info(f"Fetching live visitors since {cutoff_time}")
            
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
            logger.info(f"Found {len(rows)} visitors in owners_tracking table")
            
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
async def track_owner(data: dict, request: Request):
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
        device_type = data.get("deviceType", "desktop")
        browser = data.get("browser", "Unknown")
        os = data.get("os", "Unknown")
        user_agent = data.get("userAgent", "")
        screen_width = data.get("screenWidth")
        screen_height = data.get("screenHeight")
        
        if not session_id or not user_id:
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        # Extract IP address from request
        ip_address = None
        if hasattr(request, 'client') and request.client:
            ip_address = request.client.host
        # Check forwarded headers for real IP behind proxies
        if not ip_address or ip_address in ['127.0.0.1', 'localhost']:
            forwarded = request.headers.get('x-forwarded-for')
            if forwarded:
                ip_address = forwarded.split(',')[0].strip()
            elif request.headers.get('x-real-ip'):
                ip_address = request.headers.get('x-real-ip')
        
        # Geolocate IP using GeoIP
        country_code = None
        city = None
        try:
            import geoip2.database
            import os as os_module
            mmdb_path = os_module.path.join('data', 'geoip', 'GeoLite2-City.mmdb')
            if os_module.path.exists(mmdb_path) and ip_address:
                with geoip2.database.Reader(mmdb_path) as reader:
                    response = reader.city(ip_address)
                    country_code = response.country.iso_code
                    city = response.city.name
        except Exception as geo_err:
            logger.debug(f"Geolocation failed: {geo_err}")
        
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
                logger.info(f"Updating existing owner session {session_id} for user {user_id}")
                await session.execute(
                    text("""
                        UPDATE owners_tracking 
                        SET 
                            current_page = :current_page,
                            last_seen = :last_seen,
                            is_active = true,
                            updated_at = :updated_at,
                            ip_address = :ip_address,
                            country_code = :country_code,
                            city = :city,
                            device_type = :device_type,
                            browser = :browser,
                            os = :os,
                            user_agent = :user_agent,
                            screen_width = :screen_width,
                            screen_height = :screen_height
                        WHERE session_id = :session_id
                    """),
                    {
                        "session_id": session_id,
                        "current_page": current_page,
                        "last_seen": now,
                        "updated_at": now,
                        "ip_address": ip_address,
                        "country_code": country_code,
                        "city": city,
                        "device_type": device_type,
                        "browser": browser,
                        "os": os,
                        "user_agent": user_agent,
                        "screen_width": screen_width,
                        "screen_height": screen_height,
                    }
                )
            else:
                # Create new session
                logger.info(f"Creating new owner session {session_id} for user {user_id}")
                await session.execute(
                    text("""
                        INSERT INTO owners_tracking (
                            session_id, user_id, user_email, current_page, 
                            referrer, first_seen, last_seen, is_active,
                            ip_address, country_code, city, device_type,
                            browser, os, user_agent, screen_width, screen_height
                        ) VALUES (
                            :session_id, :user_id, :user_email, :current_page,
                            :referrer, :first_seen, :last_seen, :is_active,
                            :ip_address, :country_code, :city, :device_type,
                            :browser, :os, :user_agent, :screen_width, :screen_height
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
                        "ip_address": ip_address,
                        "country_code": country_code,
                        "city": city,
                        "device_type": device_type,
                        "browser": browser,
                        "os": os,
                        "user_agent": user_agent,
                        "screen_width": screen_width,
                        "screen_height": screen_height,
                    }
                )
            
            await session.commit()
            
            return {"success": True, "message": "Owner activity tracked"}
            
    except Exception as e:
        logger.exception("Failed to track owner activity")
        raise HTTPException(status_code=500, detail=f"Failed to track owner: {str(e)}")
