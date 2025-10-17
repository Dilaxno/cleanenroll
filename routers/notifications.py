"""
Notifications API router for reading notifications from Neon PostgreSQL
"""
from fastapi import APIRouter, HTTPException, Request, Query
from typing import Optional
from sqlalchemy import text, String, Integer, bindparam
from db.database import async_session_maker
from slowapi import Limiter
from utils.limiter import forwarded_for_ip
import logging

router = APIRouter(prefix="/api/notifications", tags=["notifications"])
limiter = Limiter(key_func=forwarded_for_ip)
logger = logging.getLogger("backend.notifications")

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
        logger.exception("Firebase token verification failed")
        raise HTTPException(status_code=401, detail="Invalid token")

@router.get("/")
@limiter.limit("120/minute")
async def list_notifications(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    unread_only: bool = Query(default=False)
):
    """
    List notifications for the authenticated user from Neon PostgreSQL.
    Returns notifications ordered by created_at DESC.
    """
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    async with async_session_maker() as session:
        # Build query based on unread filter
        if unread_only:
            query = (
                text("""
                    SELECT id, user_id, title, message, type, data, 
                           read, read_at, created_at
                    FROM notifications
                    WHERE user_id = :uid AND read = false
                    ORDER BY created_at DESC
                    LIMIT :limit_val OFFSET :offset_val
                """)
                .bindparams(
                    bindparam("uid", type_=String),
                    bindparam("limit_val", type_=Integer),
                    bindparam("offset_val", type_=Integer),
                )
            )
            result = await session.execute(query, {"uid": uid, "limit_val": limit, "offset_val": offset})
        else:
            query = (
                text("""
                    SELECT id, user_id, title, message, type, data,
                           read, read_at, created_at
                    FROM notifications
                    WHERE user_id = :uid
                    ORDER BY created_at DESC
                    LIMIT :limit_val OFFSET :offset_val
                """)
                .bindparams(
                    bindparam("uid", type_=String),
                    bindparam("limit_val", type_=Integer),
                    bindparam("offset_val", type_=Integer),
                )
            )
            result = await session.execute(query, {"uid": uid, "limit_val": limit, "offset_val": offset})
        
        rows = result.mappings().all()
        
        # Get total count
        if unread_only:
            count_query = text("SELECT COUNT(*) as cnt FROM notifications WHERE user_id = :uid AND read = false").bindparams(bindparam("uid", type_=String))
        else:
            count_query = text("SELECT COUNT(*) as cnt FROM notifications WHERE user_id = :uid").bindparams(bindparam("uid", type_=String))
        
        count_result = await session.execute(count_query, {"uid": uid})
        total = int((count_result.mappings().first() or {}).get("cnt") or 0)
        
        # Format notifications for frontend
        notifications = []
        for row in rows:
            item = {
                "id": row.get("id"),
                "title": row.get("title"),
                "message": row.get("message"),
                "type": row.get("type"),
                "read": bool(row.get("read")),
                "readAt": row.get("read_at").isoformat() if row.get("read_at") else None,
                "createdAt": row.get("created_at").isoformat() if row.get("created_at") else None,
            }
            # Parse data JSON field
            try:
                import json
                data_str = row.get("data")
                if isinstance(data_str, str):
                    data = json.loads(data_str)
                elif isinstance(data_str, dict):
                    data = data_str
                else:
                    data = {}
                item["formId"] = data.get("formId")
                item["responseId"] = data.get("responseId")
                item["preview"] = row.get("message") or ""
            except Exception:
                item["formId"] = None
                item["responseId"] = None
                item["preview"] = row.get("message") or ""
            
            notifications.append(item)
        
        return {
            "notifications": notifications,
            "total": total,
            "limit": limit,
            "offset": offset,
            "unseenCount": sum(1 for n in notifications if not n["read"])
        }

@router.post("/{notification_id}/read")
@limiter.limit("120/minute")
async def mark_notification_read(notification_id: str, request: Request):
    """Mark a notification as read."""
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    async with async_session_maker() as session:
        # Verify ownership and update
        result = await session.execute(
            text("""
                UPDATE notifications
                SET read = true, read_at = NOW()
                WHERE id = :id AND user_id = :uid
                RETURNING id
            """),
            {"id": notification_id, "uid": uid}
        )
        row = result.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Notification not found")
        
        await session.commit()
        return {"success": True}

@router.post("/mark-all-read")
@limiter.limit("60/minute")
async def mark_all_notifications_read(request: Request):
    """Mark all notifications as read for the authenticated user."""
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    async with async_session_maker() as session:
        await session.execute(
            text("""
                UPDATE notifications
                SET read = true, read_at = NOW()
                WHERE user_id = :uid AND read = false
            """),
            {"uid": uid}
        )
        await session.commit()
        return {"success": True}
