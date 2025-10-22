import logging
from fastapi import APIRouter, HTTPException, Query
from db.database import async_session_maker
from sqlalchemy import text

logger = logging.getLogger("backend.user_stats")

router = APIRouter(prefix="/api/user", tags=["user-stats"])


@router.get("/stats")
async def get_user_stats(userId: str = Query(..., description="Firebase Auth UID")):
    """Get total views and submissions for a user from Neon DB."""
    if not userId:
        raise HTTPException(status_code=400, detail="Missing userId")
    
    if async_session_maker is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    
    try:
        async with async_session_maker() as session:
            # Get total submissions count
            submissions_result = await session.execute(
                text("""
                    SELECT COUNT(*) as total
                    FROM submissions s
                    INNER JOIN forms f ON s.form_id = f.id
                    WHERE f.user_id = :user_id
                """),
                {"user_id": userId}
            )
            total_submissions = submissions_result.scalar() or 0
            
            # Get total views count
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
