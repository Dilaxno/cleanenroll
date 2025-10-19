"""
Live Visitor Tracking API
Tracks real-time visitors on form pages with geolocation data
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timedelta
import geoip2.database
import os

router = APIRouter()

class LiveVisitorPayload(BaseModel):
    sessionId: str
    action: Literal['enter', 'heartbeat', 'exit']
    timestamp: str
    userAgent: Optional[str] = None
    referrer: Optional[str] = None
    screenWidth: Optional[int] = None
    screenHeight: Optional[int] = None


def _get_client_ip(request: Request) -> str:
    """Extract real client IP from request headers"""
    # Check common proxy headers
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        # Take the first IP in the chain
        return forwarded.split(',')[0].strip()
    
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip.strip()
    
    # Fallback to direct connection
    if request.client and request.client.host:
        return request.client.host
    
    return '127.0.0.1'


def _get_location_from_ip(ip: str) -> dict:
    """
    Get city, country, coordinates from IP using GeoLite2 database
    """
    try:
        # Path to GeoLite2 City database
        db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'geoip', 'GeoLite2-City.mmdb')
        
        if not os.path.exists(db_path):
            return {
                'city': None,
                'country': None,
                'country_code': None,
                'latitude': None,
                'longitude': None,
            }
        
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip)
            
            return {
                'city': response.city.name if response.city.name else None,
                'country': response.country.name if response.country.name else None,
                'country_code': response.country.iso_code if response.country.iso_code else None,
                'latitude': response.location.latitude if response.location.latitude else None,
                'longitude': response.location.longitude if response.location.longitude else None,
            }
    except Exception as e:
        print(f"GeoIP lookup failed for {ip}: {e}")
        return {
            'city': None,
            'country': None,
            'country_code': None,
            'latitude': None,
            'longitude': None,
        }


@router.post('/api/builder/forms/{form_id}/live-visitors')
async def track_live_visitor(
    form_id: str,
    payload: LiveVisitorPayload,
    request: Request
):
    """
    Track live visitor activity on a form page
    Stores visitor session with geolocation data
    """
    from ..db.database import get_db
    
    try:
        # Get client IP and location
        ip = _get_client_ip(request)
        location = _get_location_from_ip(ip)
        
        db = get_db()
        cursor = db.cursor()
        
        # Upsert visitor session
        if payload.action == 'enter':
            # New visitor enters the form
            cursor.execute("""
                INSERT INTO live_visitors (
                    form_id, session_id, ip_address, 
                    city, country, country_code, latitude, longitude,
                    user_agent, referrer, screen_width, screen_height,
                    first_seen, last_seen, is_active
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (session_id) 
                DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    is_active = true
            """, (
                form_id,
                payload.sessionId,
                ip,
                location['city'],
                location['country'],
                location['country_code'],
                location['latitude'],
                location['longitude'],
                payload.userAgent,
                payload.referrer,
                payload.screenWidth,
                payload.screenHeight,
                payload.timestamp,
                payload.timestamp,
                True
            ))
        
        elif payload.action == 'heartbeat':
            # Update last_seen timestamp to show visitor is still active
            cursor.execute("""
                UPDATE live_visitors 
                SET last_seen = %s, is_active = true
                WHERE session_id = %s AND form_id = %s
            """, (payload.timestamp, payload.sessionId, form_id))
        
        elif payload.action == 'exit':
            # Mark visitor as inactive when they leave
            cursor.execute("""
                UPDATE live_visitors 
                SET is_active = false, last_seen = %s
                WHERE session_id = %s AND form_id = %s
            """, (payload.timestamp, payload.sessionId, form_id))
        
        db.commit()
        cursor.close()
        
        return {'success': True, 'location': location}
    
    except Exception as e:
        print(f"Error tracking live visitor: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/api/builder/forms/{form_id}/live-visitors')
async def get_live_visitors(form_id: str):
    """
    Get list of currently active visitors on a form
    Returns visitors who were active in the last 30 seconds
    """
    from ..db.database import get_db
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Consider visitors active if last_seen within 30 seconds
        threshold = (datetime.utcnow() - timedelta(seconds=30)).isoformat()
        
        cursor.execute("""
            SELECT 
                session_id, ip_address, city, country, country_code,
                latitude, longitude, user_agent, referrer,
                screen_width, screen_height, first_seen, last_seen
            FROM live_visitors
            WHERE form_id = %s 
                AND is_active = true 
                AND last_seen >= %s
            ORDER BY last_seen DESC
        """, (form_id, threshold))
        
        rows = cursor.fetchall()
        cursor.close()
        
        visitors = []
        for row in rows:
            visitors.append({
                'sessionId': row[0],
                'ipAddress': row[1],
                'city': row[2],
                'country': row[3],
                'countryCode': row[4],
                'latitude': row[5],
                'longitude': row[6],
                'userAgent': row[7],
                'referrer': row[8],
                'screenWidth': row[9],
                'screenHeight': row[10],
                'firstSeen': row[11].isoformat() if row[11] else None,
                'lastSeen': row[12].isoformat() if row[12] else None,
            })
        
        return {
            'success': True,
            'visitors': visitors,
            'count': len(visitors)
        }
    
    except Exception as e:
        print(f"Error fetching live visitors: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete('/api/builder/forms/{form_id}/live-visitors/cleanup')
async def cleanup_old_visitors(form_id: str):
    """
    Clean up old visitor records (older than 1 hour)
    This can be called periodically to keep the table clean
    """
    from ..db.database import get_db
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Delete records older than 1 hour
        threshold = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        
        cursor.execute("""
            DELETE FROM live_visitors
            WHERE form_id = %s AND last_seen < %s
        """, (form_id, threshold))
        
        deleted_count = cursor.rowcount
        db.commit()
        cursor.close()
        
        return {
            'success': True,
            'deletedCount': deleted_count
        }
    
    except Exception as e:
        print(f"Error cleaning up old visitors: {e}")
        raise HTTPException(status_code=500, detail=str(e))
