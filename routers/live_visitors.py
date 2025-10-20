"""
Live Visitor Tracking API
Tracks real-time visitors on form pages with geolocation data
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timedelta
import os
import requests
from sqlalchemy import text

# Support both package and flat imports for the session maker
try:
    from db.database import async_session_maker  # type: ignore
except Exception:
    from ..db.database import async_session_maker  # type: ignore

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
    Get city, country, coordinates from IP using IPinfo API
    """
    try:
        # Get IPinfo API token from environment
        ipinfo_token = os.getenv('IPINFO_API_TOKEN', '')
        
        if not ipinfo_token:
            print("Warning: IPINFO_API_TOKEN not set in environment")
            return {
                'city': None,
                'country': None,
                'country_code': None,
                'latitude': None,
                'longitude': None,
            }
        
        # Skip localhost/private IPs
        if ip in ('127.0.0.1', 'localhost') or ip.startswith('192.168.') or ip.startswith('10.'):
            return {
                'city': 'Local',
                'country': 'Local Network',
                'country_code': 'XX',
                'latitude': None,
                'longitude': None,
            }
        
        # Call IPinfo API
        response = requests.get(
            f'https://ipinfo.io/{ip}/json',
            params={'token': ipinfo_token},
            timeout=3
        )
        
        if response.status_code != 200:
            raise Exception(f"IPinfo API returned {response.status_code}")
        
        data = response.json()
        
        # Parse location coordinates (format: "lat,lng")
        latitude = None
        longitude = None
        if 'loc' in data and data['loc']:
            try:
                lat_str, lng_str = data['loc'].split(',')
                latitude = float(lat_str)
                longitude = float(lng_str)
            except Exception:
                pass
        
        return {
            'city': data.get('city'),
            'country': data.get('country_name') or data.get('country'),
            'country_code': data.get('country'),
            'latitude': latitude,
            'longitude': longitude,
        }
    except Exception as e:
        print(f"IPinfo lookup failed for {ip}: {e}")
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
    try:
        # Get client IP and location
        ip = _get_client_ip(request)
        print(f"[LiveVisitor] Tracking {payload.action} for session {payload.sessionId}, IP: {ip}")
        
        location = _get_location_from_ip(ip)
        print(f"[LiveVisitor] Location lookup result: {location}")
        
        # Convert ISO timestamp string to datetime object for asyncpg
        # Remove timezone info to match TIMESTAMP (not TIMESTAMPTZ) columns in DB
        try:
            timestamp_dt = datetime.fromisoformat(payload.timestamp.replace('Z', '+00:00')).replace(tzinfo=None)
        except Exception as e:
            print(f"[LiveVisitor] Timestamp parsing failed: {e}, using current time")
            timestamp_dt = datetime.utcnow()
        
        async with async_session_maker() as session:
            # Upsert visitor session
            if payload.action == 'enter':
                # New visitor enters the form
                await session.execute(
                    text("""
                        INSERT INTO live_visitors (
                            form_id, session_id, ip_address, 
                            city, country, country_code, latitude, longitude,
                            user_agent, referrer, screen_width, screen_height,
                            first_seen, last_seen, is_active
                        ) VALUES (:form_id, :session_id, :ip_address, :city, :country, :country_code, 
                                  :latitude, :longitude, :user_agent, :referrer, :screen_width, 
                                  :screen_height, :first_seen, :last_seen, :is_active)
                        ON CONFLICT (session_id) 
                        DO UPDATE SET
                            last_seen = EXCLUDED.last_seen,
                            is_active = true
                    """),
                    {
                        'form_id': form_id,
                        'session_id': payload.sessionId,
                        'ip_address': ip,
                        'city': location['city'],
                        'country': location['country'],
                        'country_code': location['country_code'],
                        'latitude': location['latitude'],
                        'longitude': location['longitude'],
                        'user_agent': payload.userAgent,
                        'referrer': payload.referrer,
                        'screen_width': payload.screenWidth,
                        'screen_height': payload.screenHeight,
                        'first_seen': timestamp_dt,
                        'last_seen': timestamp_dt,
                        'is_active': True
                    }
                )
            
            elif payload.action == 'heartbeat':
                # Update last_seen timestamp to show visitor is still active
                await session.execute(
                    text("""
                        UPDATE live_visitors 
                        SET last_seen = :last_seen, is_active = true
                        WHERE session_id = :session_id AND form_id = :form_id
                    """),
                    {
                        'last_seen': timestamp_dt,
                        'session_id': payload.sessionId,
                        'form_id': form_id
                    }
                )
            
            elif payload.action == 'exit':
                # Mark visitor as inactive when they leave
                await session.execute(
                    text("""
                        UPDATE live_visitors 
                        SET is_active = false, last_seen = :last_seen
                        WHERE session_id = :session_id AND form_id = :form_id
                    """),
                    {
                        'last_seen': timestamp_dt,
                        'session_id': payload.sessionId,
                        'form_id': form_id
                    }
                )
            
            await session.commit()
        
        print(f"[LiveVisitor] Successfully tracked {payload.action} for session {payload.sessionId}")
        return {'success': True, 'location': location}
    
    except Exception as e:
        print(f"[LiveVisitor] ERROR tracking visitor: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/api/builder/forms/{form_id}/live-visitors')
async def get_live_visitors(form_id: str):
    """
    Get list of currently active visitors on a form
    Returns visitors who were active in the last 30 seconds
    """
    try:
        # Consider visitors active if last_seen within 30 seconds
        # Pass datetime object, not ISO string, for asyncpg
        threshold = datetime.utcnow() - timedelta(seconds=30)
        
        async with async_session_maker() as session:
            # Handle 'all' form_id by fetching visitors across all forms
            if form_id == 'all':
                result = await session.execute(
                    text("""
                        SELECT 
                            session_id, ip_address, city, country, country_code,
                            latitude, longitude, user_agent, referrer,
                            screen_width, screen_height, first_seen, last_seen
                        FROM live_visitors
                        WHERE is_active = true 
                            AND last_seen >= :threshold
                        ORDER BY last_seen DESC
                    """),
                    {'threshold': threshold}
                )
            else:
                result = await session.execute(
                    text("""
                        SELECT 
                            session_id, ip_address, city, country, country_code,
                            latitude, longitude, user_agent, referrer,
                            screen_width, screen_height, first_seen, last_seen
                        FROM live_visitors
                        WHERE form_id = :form_id 
                            AND is_active = true 
                            AND last_seen >= :threshold
                        ORDER BY last_seen DESC
                    """),
                    {'form_id': form_id, 'threshold': threshold}
                )
            
            rows = result.fetchall()
        
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
    try:
        # Delete records older than 1 hour
        # Pass datetime object, not ISO string, for asyncpg
        threshold = datetime.utcnow() - timedelta(hours=1)
        
        async with async_session_maker() as session:
            result = await session.execute(
                text("""
                    DELETE FROM live_visitors
                    WHERE form_id = :form_id AND last_seen < :threshold
                """),
                {'form_id': form_id, 'threshold': threshold}
            )
            
            deleted_count = result.rowcount
            await session.commit()
        
        return {
            'success': True,
            'deletedCount': deleted_count
        }
    
    except Exception as e:
        print(f"Error cleaning up old visitors: {e}")
        raise HTTPException(status_code=500, detail=str(e))
