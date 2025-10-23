import logging
from fastapi import APIRouter, HTTPException, Query
from db.database import async_session_maker
from sqlalchemy import text
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("backend.user_stats")

router = APIRouter(prefix="/api/user", tags=["user-stats"])


@router.get("/stats")
async def get_user_stats(
    userId: str = Query(..., description="Firebase Auth UID"),
    fromDate: Optional[str] = Query(None, description="Filter from date (ISO format)"),
    toDate: Optional[str] = Query(None, description="Filter to date (ISO format)")
):
    """Get total views and submissions for a user from Neon DB, optionally filtered by date range."""
    if not userId:
        raise HTTPException(status_code=400, detail="Missing userId")
    
    if async_session_maker is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    
    try:
        # Parse date filters if provided
        from_ts = None
        to_ts = None
        
        if fromDate:
            try:
                from_ts = datetime.fromisoformat(fromDate.replace('Z', '+00:00'))
            except Exception:
                logger.warning("Invalid fromDate format: %s", fromDate)
        
        if toDate:
            try:
                to_ts = datetime.fromisoformat(toDate.replace('Z', '+00:00'))
            except Exception:
                logger.warning("Invalid toDate format: %s", toDate)
        
        async with async_session_maker() as session:
            # Build submissions query with optional date filter
            submissions_query = """
                SELECT COUNT(*) as total
                FROM submissions s
                INNER JOIN forms f ON s.form_id = f.id
                WHERE f.user_id = :user_id
            """
            submissions_params = {"user_id": userId}
            
            if from_ts:
                submissions_query += " AND s.submitted_at >= :from_date"
                submissions_params["from_date"] = from_ts
            
            if to_ts:
                submissions_query += " AND s.submitted_at <= :to_date"
                submissions_params["to_date"] = to_ts
            
            submissions_result = await session.execute(
                text(submissions_query),
                submissions_params
            )
            total_submissions = submissions_result.scalar() or 0
            
            # For views, count analytics events of type 'view' within date range
            # If no date filter, fall back to cached views count from forms table
            if from_ts or to_ts:
                views_query = """
                    SELECT COUNT(*) as total
                    FROM analytics a
                    INNER JOIN forms f ON a.form_id = f.id
                    WHERE f.user_id = :user_id
                      AND a.type = 'view'
                """
                views_params = {"user_id": userId}
                
                if from_ts:
                    views_query += " AND a.ts >= :from_date"
                    views_params["from_date"] = from_ts
                
                if to_ts:
                    views_query += " AND a.ts <= :to_date"
                    views_params["to_date"] = to_ts
                
                views_result = await session.execute(
                    text(views_query),
                    views_params
                )
                total_views = views_result.scalar() or 0
            else:
                # No date filter - use cached sum from forms table
                views_result = await session.execute(
                    text("""
                        SELECT COALESCE(SUM(views), 0) as total
                        FROM forms
                        WHERE user_id = :user_id
                    """),
                    {"user_id": userId}
                )
                total_views = views_result.scalar() or 0
            
            return {
                "totalSubmissions": int(total_submissions),
                "totalViews": int(total_views)
            }
    except Exception as e:
        logger.exception("Failed to fetch user stats from Neon")
        raise HTTPException(status_code=500, detail=f"Failed to fetch stats: {str(e)}")
