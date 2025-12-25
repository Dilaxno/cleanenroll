"""
OAuth 2.0 Protected API Endpoints for CleanEnroll
REST API endpoints protected with Bearer token authentication
"""
from fastapi import APIRouter, Depends, HTTPException, Header, Request, Query
from typing import Optional, List
from db.database import async_session_maker
from sqlalchemy import text
from services.oauth_service import oauth_service
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v2", tags=["OAuth Protected API"])


async def get_oauth_token_data(authorization: str = Header(None)) -> dict:
    """Dependency to validate OAuth access token and return token data"""
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "Missing authorization header"},
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "Invalid authorization scheme"},
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = authorization.replace("Bearer ", "")
    token_data = await oauth_service.validate_access_token(token)
    
    if not token_data:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "Token is invalid or expired"},
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""}
        )
    
    return token_data


def require_scope(required_scope: str):
    """Dependency factory to require specific scope"""
    async def check_scope(token_data: dict = Depends(get_oauth_token_data)):
        scopes = token_data.get("scope", "").split()
        if required_scope not in scopes:
            raise HTTPException(
                status_code=403,
                detail={"error": "insufficient_scope", "error_description": f"Scope '{required_scope}' required"}
            )
        return token_data
    return check_scope


# ============== FORMS API ==============

@router.get("/forms")
async def list_forms(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    token_data: dict = Depends(require_scope("forms:read"))
):
    """List all forms for the authenticated user"""
    user_id = token_data["user_id"]
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""SELECT id, title, name, description, form_type, is_published,
                          views, submissions, created_at, updated_at
                   FROM forms WHERE user_id = :user_id
                   ORDER BY created_at DESC
                   LIMIT :limit OFFSET :offset"""),
            {"user_id": user_id, "limit": limit, "offset": offset}
        )
        rows = result.fetchall()
        
        # Get total count
        count_result = await session.execute(
            text("SELECT COUNT(*) FROM forms WHERE user_id = :user_id"),
            {"user_id": user_id}
        )
        total = count_result.scalar()
        
        return {
            "data": [
                {
                    "id": r[0],
                    "title": r[1],
                    "name": r[2],
                    "description": r[3],
                    "form_type": r[4],
                    "is_published": r[5],
                    "views": r[6],
                    "submissions": r[7],
                    "created_at": r[8].isoformat() if r[8] else None,
                    "updated_at": r[9].isoformat() if r[9] else None,
                }
                for r in rows
            ],
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + limit < total
            }
        }


@router.get("/forms/{form_id}")
async def get_form(
    form_id: str,
    token_data: dict = Depends(require_scope("forms:read"))
):
    """Get a specific form by ID"""
    user_id = token_data["user_id"]
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""SELECT id, title, name, description, form_type, is_published,
                          views, submissions, fields, theme, branding,
                          created_at, updated_at
                   FROM forms WHERE id = :form_id AND user_id = :user_id"""),
            {"form_id": form_id, "user_id": user_id}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Form not found")
        
        return {
            "id": row[0],
            "title": row[1],
            "name": row[2],
            "description": row[3],
            "form_type": row[4],
            "is_published": row[5],
            "views": row[6],
            "submissions": row[7],
            "fields": row[8],
            "theme": row[9],
            "branding": row[10],
            "created_at": row[11].isoformat() if row[11] else None,
            "updated_at": row[12].isoformat() if row[12] else None,
        }


# ============== SUBMISSIONS API ==============

@router.get("/forms/{form_id}/submissions")
async def list_submissions(
    form_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    token_data: dict = Depends(require_scope("submissions:read"))
):
    """List submissions for a specific form"""
    user_id = token_data["user_id"]
    
    async with async_session_maker() as session:
        # Verify form ownership
        form_check = await session.execute(
            text("SELECT id FROM forms WHERE id = :form_id AND user_id = :user_id"),
            {"form_id": form_id, "user_id": user_id}
        )
        if not form_check.fetchone():
            raise HTTPException(status_code=404, detail="Form not found")
        
        result = await session.execute(
            text("""SELECT id, data, metadata, ip_address, country_code,
                          user_agent, submitted_at
                   FROM submissions WHERE form_id = :form_id
                   ORDER BY submitted_at DESC
                   LIMIT :limit OFFSET :offset"""),
            {"form_id": form_id, "limit": limit, "offset": offset}
        )
        rows = result.fetchall()
        
        count_result = await session.execute(
            text("SELECT COUNT(*) FROM submissions WHERE form_id = :form_id"),
            {"form_id": form_id}
        )
        total = count_result.scalar()
        
        return {
            "data": [
                {
                    "id": r[0],
                    "data": r[1],
                    "metadata": r[2],
                    "ip_address": str(r[3]) if r[3] else None,
                    "country_code": r[4],
                    "user_agent": r[5],
                    "submitted_at": r[6].isoformat() if r[6] else None,
                }
                for r in rows
            ],
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + limit < total
            }
        }


@router.get("/submissions/{submission_id}")
async def get_submission(
    submission_id: str,
    token_data: dict = Depends(require_scope("submissions:read"))
):
    """Get a specific submission by ID"""
    user_id = token_data["user_id"]
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""SELECT s.id, s.form_id, s.data, s.metadata, s.ip_address,
                          s.country_code, s.user_agent, s.submitted_at
                   FROM submissions s
                   JOIN forms f ON s.form_id = f.id
                   WHERE s.id = :submission_id AND f.user_id = :user_id"""),
            {"submission_id": submission_id, "user_id": user_id}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Submission not found")
        
        return {
            "id": row[0],
            "form_id": row[1],
            "data": row[2],
            "metadata": row[3],
            "ip_address": str(row[4]) if row[4] else None,
            "country_code": row[5],
            "user_agent": row[6],
            "submitted_at": row[7].isoformat() if row[7] else None,
        }


# ============== ANALYTICS API ==============

@router.get("/forms/{form_id}/analytics")
async def get_form_analytics(
    form_id: str,
    days: int = Query(30, ge=1, le=90),
    token_data: dict = Depends(require_scope("analytics:read"))
):
    """Get analytics for a specific form"""
    user_id = token_data["user_id"]
    
    async with async_session_maker() as session:
        # Verify form ownership
        form_check = await session.execute(
            text("SELECT id, views, submissions FROM forms WHERE id = :form_id AND user_id = :user_id"),
            {"form_id": form_id, "user_id": user_id}
        )
        form_row = form_check.fetchone()
        if not form_row:
            raise HTTPException(status_code=404, detail="Form not found")
        
        # Get daily views
        views_result = await session.execute(
            text("""SELECT DATE(ts) as date, COUNT(*) as count
                   FROM analytics
                   WHERE form_id = :form_id AND type = 'view'
                   AND ts >= NOW() - INTERVAL ':days days'
                   GROUP BY DATE(ts)
                   ORDER BY date"""),
            {"form_id": form_id, "days": days}
        )
        daily_views = [{"date": str(r[0]), "count": r[1]} for r in views_result.fetchall()]
        
        # Get daily submissions
        submissions_result = await session.execute(
            text("""SELECT DATE(submitted_at) as date, COUNT(*) as count
                   FROM submissions
                   WHERE form_id = :form_id
                   AND submitted_at >= NOW() - INTERVAL ':days days'
                   GROUP BY DATE(submitted_at)
                   ORDER BY date"""),
            {"form_id": form_id, "days": days}
        )
        daily_submissions = [{"date": str(r[0]), "count": r[1]} for r in submissions_result.fetchall()]
        
        # Get country breakdown
        country_result = await session.execute(
            text("""SELECT country_code, COUNT(*) as count
                   FROM submissions
                   WHERE form_id = :form_id AND country_code IS NOT NULL
                   GROUP BY country_code
                   ORDER BY count DESC
                   LIMIT 10"""),
            {"form_id": form_id}
        )
        countries = [{"country": r[0], "count": r[1]} for r in country_result.fetchall()]
        
        total_views = form_row[1] or 0
        total_submissions = form_row[2] or 0
        conversion_rate = (total_submissions / total_views * 100) if total_views > 0 else 0
        
        return {
            "form_id": form_id,
            "period_days": days,
            "summary": {
                "total_views": total_views,
                "total_submissions": total_submissions,
                "conversion_rate": round(conversion_rate, 2)
            },
            "daily_views": daily_views,
            "daily_submissions": daily_submissions,
            "top_countries": countries
        }


# ============== PAYMENTS API ==============

@router.get("/payments")
async def list_payments(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    token_data: dict = Depends(require_scope("payments:read"))
):
    """List payments for the authenticated user's forms"""
    user_id = token_data["user_id"]
    
    async with async_session_maker() as session:
        # Check if payments table exists and get data
        try:
            result = await session.execute(
                text("""SELECT p.id, p.form_id, p.amount, p.currency, p.status,
                              p.customer_email, p.created_at
                       FROM payments p
                       JOIN forms f ON p.form_id = f.id
                       WHERE f.user_id = :user_id
                       ORDER BY p.created_at DESC
                       LIMIT :limit OFFSET :offset"""),
                {"user_id": user_id, "limit": limit, "offset": offset}
            )
            rows = result.fetchall()
            
            return {
                "data": [
                    {
                        "id": r[0],
                        "form_id": r[1],
                        "amount": r[2],
                        "currency": r[3],
                        "status": r[4],
                        "customer_email": r[5],
                        "created_at": r[6].isoformat() if r[6] else None,
                    }
                    for r in rows
                ],
                "pagination": {
                    "total": len(rows),
                    "limit": limit,
                    "offset": offset
                }
            }
        except Exception:
            # Payments table may not exist
            return {"data": [], "pagination": {"total": 0, "limit": limit, "offset": offset}}


# ============== USER PROFILE API ==============

@router.get("/me")
async def get_current_user(token_data: dict = Depends(require_scope("profile:read"))):
    """Get current user profile"""
    user_id = token_data["user_id"]
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""SELECT uid, email, display_name, photo_url, plan,
                          forms_count, created_at
                   FROM users WHERE uid = :user_id"""),
            {"user_id": user_id}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "id": row[0],
            "email": row[1],
            "display_name": row[2],
            "photo_url": row[3],
            "plan": row[4],
            "forms_count": row[5],
            "created_at": row[6].isoformat() if row[6] else None,
        }
