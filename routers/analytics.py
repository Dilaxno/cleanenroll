"""
Analytics API router for reading analytics data from Neon PostgreSQL
"""
from fastapi import APIRouter, HTTPException, Request, Query
from typing import Optional
from datetime import datetime
from sqlalchemy import text
from db.database import async_session_maker
from slowapi import Limiter
from utils.limiter import forwarded_for_ip
import logging

router = APIRouter(prefix="/api/builder/forms", tags=["analytics"])
limiter = Limiter(key_func=forwarded_for_ip)
logger = logging.getLogger("backend.analytics")

def _verify_firebase_uid(request: Request) -> str:
    """Extract and verify Firebase UID from Authorization header."""
    try:
        from firebase_admin import auth as _admin_auth  # type: ignore
    except Exception as e:
        logger.error(f"Firebase Admin import failed: {e}")
        raise HTTPException(status_code=500, detail="Firebase Admin not available on server")
    
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authz or not authz.lower().startswith("bearer "):
        logger.warning(f"Missing or invalid auth header: {authz[:20] if authz else 'None'}...")
        raise HTTPException(status_code=401, detail="Missing Authorization token")
    
    token = authz.split(" ", 1)[1].strip()
    try:
        decoded = _admin_auth.verify_id_token(token)
        uid = decoded.get("uid")
        if not uid:
            logger.error("Token decoded but no uid found")
            raise HTTPException(status_code=401, detail="Invalid token")
        return uid
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firebase token verification failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")

@router.get("/{form_id}/analytics/countries")
@limiter.limit("120/minute")
async def get_form_countries_analytics(
    form_id: str,
    request: Request,
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to")
):
    """
    Get aggregated country submission counts for a form within a date range.
    Returns country_iso2 codes and their submission counts.
    Counts directly from submissions table to ensure ALL submissions are included.
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
        
        # Parse date range
        try:
            if from_date:
                from_dt = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            else:
                from_dt = None
            
            if to_date:
                to_dt = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
            else:
                to_dt = None
        except Exception:
            from_dt = None
            to_dt = None
        
        # Count directly from submissions table to show ALL submissions (not cached aggregates)
        if from_dt and to_dt:
            query = text("""
                SELECT country_code, COUNT(*) as total
                FROM submissions
                WHERE form_id = :fid AND submitted_at >= :from_dt AND submitted_at <= :to_dt
                  AND country_code IS NOT NULL AND country_code != ''
                GROUP BY country_code
                ORDER BY total DESC
            """)
            result = await session.execute(query, {"fid": form_id, "from_dt": from_dt, "to_dt": to_dt})
        elif from_dt:
            query = text("""
                SELECT country_code, COUNT(*) as total
                FROM submissions
                WHERE form_id = :fid AND submitted_at >= :from_dt
                  AND country_code IS NOT NULL AND country_code != ''
                GROUP BY country_code
                ORDER BY total DESC
            """)
            result = await session.execute(query, {"fid": form_id, "from_dt": from_dt})
        elif to_dt:
            query = text("""
                SELECT country_code, COUNT(*) as total
                FROM submissions
                WHERE form_id = :fid AND submitted_at <= :to_dt
                  AND country_code IS NOT NULL AND country_code != ''
                GROUP BY country_code
                ORDER BY total DESC
            """)
            result = await session.execute(query, {"fid": form_id, "to_dt": to_dt})
        else:
            # No date filter: show ALL submissions from Neon DB
            query = text("""
                SELECT country_code, COUNT(*) as total
                FROM submissions
                WHERE form_id = :fid
                  AND country_code IS NOT NULL AND country_code != ''
                GROUP BY country_code
                ORDER BY total DESC
            """)
            result = await session.execute(query, {"fid": form_id})
        
        rows = result.mappings().all()
        
        # Format as { "US": 10, "CA": 5, ... }
        countries = {}
        for row in rows:
            iso = row.get("country_code")
            total = int(row.get("total") or 0)
            if iso and total > 0:
                countries[str(iso).upper()] = total
        
        return {"countries": countries}

@router.get("/{form_id}/analytics/markers")
@limiter.limit("120/minute")
async def get_form_submission_markers(
    form_id: str,
    request: Request,
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
    limit: int = Query(1000, le=5000)
):
    """
    Get submission markers (lat/lon) for map visualization.
    Returns array of {lat, lon, country_code, created_at}.
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
        
        # Parse date range
        try:
            if from_date:
                from_dt = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            else:
                from_dt = None
            
            if to_date:
                to_dt = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
            else:
                to_dt = None
        except Exception:
            from_dt = None
            to_dt = None
        
        # Build query based on date range
        if from_dt and to_dt:
            query = text("""
                SELECT lat, lon, country_code, created_at
                FROM submission_markers
                WHERE form_id = :fid AND created_at >= :from_dt AND created_at <= :to_dt
                ORDER BY created_at DESC
                LIMIT :limit
            """)
            result = await session.execute(query, {"fid": form_id, "from_dt": from_dt, "to_dt": to_dt, "limit": limit})
        elif from_dt:
            query = text("""
                SELECT lat, lon, country_code, created_at
                FROM submission_markers
                WHERE form_id = :fid AND created_at >= :from_dt
                ORDER BY created_at DESC
                LIMIT :limit
            """)
            result = await session.execute(query, {"fid": form_id, "from_dt": from_dt, "limit": limit})
        elif to_dt:
            query = text("""
                SELECT lat, lon, country_code, created_at
                FROM submission_markers
                WHERE form_id = :fid AND created_at <= :to_dt
                ORDER BY created_at DESC
                LIMIT :limit
            """)
            result = await session.execute(query, {"fid": form_id, "to_dt": to_dt, "limit": limit})
        else:
            query = text("""
                SELECT lat, lon, country_code, created_at
                FROM submission_markers
                WHERE form_id = :fid
                ORDER BY created_at DESC
                LIMIT :limit
            """)
            result = await session.execute(query, {"fid": form_id, "limit": limit})
        
        rows = result.mappings().all()
        
        # Format markers
        markers = []
        for row in rows:
            lat = row.get("lat")
            lon = row.get("lon")
            if lat is not None and lon is not None:
                markers.append({
                    "lat": float(lat),
                    "lon": float(lon),
                    "country_code": row.get("country_code"),
                    "created_at": row.get("created_at").isoformat() if row.get("created_at") else None
                })
        
        return {"markers": markers}
