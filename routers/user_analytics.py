"""
User-level analytics API for aggregating analytics across all forms owned by a user
"""
from fastapi import APIRouter, HTTPException, Request, Query
from typing import Optional
from datetime import datetime, timedelta
from sqlalchemy import text
from db.database import async_session_maker
from slowapi import Limiter
from utils.limiter import forwarded_for_ip
import logging

router = APIRouter(prefix="/api/user", tags=["user-analytics"])
limiter = Limiter(key_func=forwarded_for_ip)
logger = logging.getLogger("backend.user_analytics")

def _verify_firebase_uid(request: Request) -> str:
    """Extract and verify Firebase UID from Authorization header."""
    try:
        from firebase_admin import auth as _admin_auth  # type: ignore
    except Exception as e:
        logger.error(f"Firebase Admin import failed: {e}")
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
    except Exception as e:
        logger.error(f"Firebase token verification failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/analytics")
@limiter.limit("60/minute")
async def get_user_analytics(
    request: Request,
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
    form_id: Optional[str] = Query(None, description="Optional: filter by specific form ID")
):
    """
    Get aggregated analytics for all forms owned by the user.
    Returns views, submissions, countries, and time-series data.
    """
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    async with async_session_maker() as session:
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
        
        # Build WHERE clause for date filtering
        date_filter = ""
        params = {"uid": uid}
        
        if form_id:
            params["form_id"] = form_id
            
        if from_dt and to_dt:
            date_filter = "AND a.created_at >= :from_dt AND a.created_at <= :to_dt"
            params["from_dt"] = from_dt
            params["to_dt"] = to_dt
        elif from_dt:
            date_filter = "AND a.created_at >= :from_dt"
            params["from_dt"] = from_dt
        elif to_dt:
            date_filter = "AND a.created_at <= :to_dt"
            params["to_dt"] = to_dt
        
        # Count total views from analytics table
        form_filter = "AND f.id = :form_id" if form_id else ""
        
        views_query = text(f"""
            SELECT COUNT(*) as total
            FROM analytics a
            INNER JOIN forms f ON a.form_id = f.id
            WHERE f.user_id = :uid
              AND a.type = 'view'
              {form_filter}
              {date_filter}
        """)
        views_result = await session.execute(views_query, params)
        total_views = views_result.scalar() or 0
        
        # Count total submissions
        sub_date_filter = date_filter.replace("a.created_at", "s.submitted_at")
        submissions_query = text(f"""
            SELECT COUNT(*) as total
            FROM submissions s
            INNER JOIN forms f ON s.form_id = f.id
            WHERE f.user_id = :uid
              {form_filter.replace("f.id", "s.form_id")}
              {sub_date_filter}
        """)
        submissions_result = await session.execute(submissions_query, params)
        total_submissions = submissions_result.scalar() or 0
        
        # Count starts (form_started events)
        starts_query = text(f"""
            SELECT COUNT(*) as total
            FROM analytics a
            INNER JOIN forms f ON a.form_id = f.id
            WHERE f.user_id = :uid
              AND a.type = 'form_started'
              {form_filter}
              {date_filter}
        """)
        starts_result = await session.execute(starts_query, params)
        total_starts = starts_result.scalar() or 0
        
        # Calculate conversion rate
        conversion_rate = (total_submissions / total_starts * 100) if total_starts > 0 else 0
        
        # Get country distribution from submissions
        countries_query = text(f"""
            SELECT s.country_code, COUNT(*) as count
            FROM submissions s
            INNER JOIN forms f ON s.form_id = f.id
            WHERE f.user_id = :uid
              {form_filter.replace("f.id", "s.form_id")}
              {sub_date_filter}
              AND s.country_code IS NOT NULL
              AND s.country_code != ''
            GROUP BY s.country_code
            ORDER BY count DESC
        """)
        countries_result = await session.execute(countries_query, params)
        countries_rows = countries_result.mappings().all()
        
        countries = {}
        for row in countries_rows:
            iso = row.get("country_code")
            count = int(row.get("count") or 0)
            if iso:
                countries[str(iso).upper()] = count
        
        # Get daily time series data for charts
        # Group by day for views and submissions
        daily_query = text(f"""
            WITH daily_views AS (
                SELECT DATE(a.created_at) as day, COUNT(*) as views
                FROM analytics a
                INNER JOIN forms f ON a.form_id = f.id
                WHERE f.user_id = :uid
                  AND a.type = 'view'
                  {form_filter}
                  {date_filter}
                GROUP BY DATE(a.created_at)
            ),
            daily_subs AS (
                SELECT DATE(s.submitted_at) as day, COUNT(*) as submissions
                FROM submissions s
                INNER JOIN forms f ON s.form_id = f.id
                WHERE f.user_id = :uid
                  {form_filter.replace("f.id", "s.form_id")}
                  {sub_date_filter}
                GROUP BY DATE(s.submitted_at)
            )
            SELECT 
                COALESCE(v.day, s.day) as day,
                COALESCE(v.views, 0) as views,
                COALESCE(s.submissions, 0) as submissions
            FROM daily_views v
            FULL OUTER JOIN daily_subs s ON v.day = s.day
            ORDER BY day ASC
        """)
        daily_result = await session.execute(daily_query, params)
        daily_rows = daily_result.mappings().all()
        
        # Format time series data
        points = []
        for row in daily_rows:
            day = row.get("day")
            if day:
                points.append({
                    "date": day.isoformat() if hasattr(day, 'isoformat') else str(day),
                    "views": int(row.get("views") or 0),
                    "submissions": int(row.get("submissions") or 0)
                })
        
        return {
            "totals": {
                "views": total_views,
                "starts": total_starts,
                "submissions": total_submissions,
                "conversionRate": round(conversion_rate, 2)
            },
            "countries": countries,
            "points": points,
            "dateRange": {
                "from": from_dt.isoformat() if from_dt else None,
                "to": to_dt.isoformat() if to_dt else None
            }
        }
