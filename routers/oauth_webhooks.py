"""
OAuth Webhook Management Router for CleanEnroll
Handles webhook registration and event delivery
"""
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from typing import List, Optional
from db.database import async_session_maker
from sqlalchemy import text
import json

from models.oauth import RegisterWebhookRequest, WebhookEventType, WebhookResponse
from services.oauth_service import oauth_service, webhook_service

router = APIRouter(prefix="/api/developer/oauth", tags=["OAuth Webhooks"])


def _get_uid_from_token(authorization: str = Header(None)) -> str:
    """Extract and verify Firebase token, return UID"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    try:
        import firebase_admin.auth as firebase_auth
        decoded_token = firebase_auth.verify_id_token(token)
        return decoded_token["uid"]
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


@router.post("/clients/{client_id}/webhook")
async def register_webhook(
    client_id: str,
    request: RegisterWebhookRequest,
    authorization: str = Header(...)
):
    """Register or update webhook URL for an OAuth client"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        # Verify ownership and get current webhook secret
        result = await session.execute(
            text("""SELECT id, webhook_secret FROM oauth_clients
                   WHERE client_id = :client_id AND user_id = :uid"""),
            {"client_id": client_id, "uid": uid}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="OAuth client not found")

        webhook_secret = row[1]
        if not webhook_secret:
            webhook_secret = oauth_service.generate_webhook_secret()
        
        # Update webhook URL
        await session.execute(
            text("""UPDATE oauth_clients
                   SET webhook_url = :webhook_url, webhook_secret = :webhook_secret,
                       updated_at = NOW()
                   WHERE client_id = :client_id"""),
            {"webhook_url": request.url, "webhook_secret": webhook_secret, "client_id": client_id}
        )
        await session.commit()
        
        return {
            "client_id": client_id,
            "webhook_url": request.url,
            "webhook_secret": webhook_secret,
            "events": request.events,
            "message": "Webhook registered. Use the webhook_secret to verify signatures."
        }


@router.get("/clients/{client_id}/webhook")
async def get_webhook(client_id: str, authorization: str = Header(...)):
    """Get webhook configuration for an OAuth client"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""SELECT webhook_url, webhook_secret, created_at
                   FROM oauth_clients
                   WHERE client_id = :client_id AND user_id = :uid"""),
            {"client_id": client_id, "uid": uid}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="OAuth client not found")
        
        if not row[0]:
            return {"webhook_url": None, "is_configured": False}
        
        return {
            "webhook_url": row[0],
            "webhook_secret": row[1],
            "is_configured": True,
            "available_events": [e.value for e in WebhookEventType]
        }


@router.delete("/clients/{client_id}/webhook")
async def delete_webhook(client_id: str, authorization: str = Header(...)):
    """Remove webhook configuration for an OAuth client"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""UPDATE oauth_clients
                   SET webhook_url = NULL, updated_at = NOW()
                   WHERE client_id = :client_id AND user_id = :uid
                   RETURNING id"""),
            {"client_id": client_id, "uid": uid}
        )
        row = result.fetchone()
        await session.commit()
        
        if not row:
            raise HTTPException(status_code=404, detail="OAuth client not found")
        
        return {"message": "Webhook removed successfully"}


@router.get("/clients/{client_id}/webhook/events")
async def list_webhook_events(
    client_id: str,
    status: Optional[str] = None,
    limit: int = 50,
    authorization: str = Header(...)
):
    """List webhook events for an OAuth client"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        # Verify ownership
        owner_check = await session.execute(
            text("SELECT id FROM oauth_clients WHERE client_id = :client_id AND user_id = :uid"),
            {"client_id": client_id, "uid": uid}
        )
        if not owner_check.fetchone():
            raise HTTPException(status_code=404, detail="OAuth client not found")
        
        query = """SELECT id, event_type, payload, status, attempts,
                         last_attempt_at, delivered_at, error_message, created_at
                  FROM oauth_webhook_events
                  WHERE client_id = :client_id"""
        params = {"client_id": client_id, "limit": limit}
        
        if status:
            query += " AND status = :status"
            params["status"] = status
        
        query += " ORDER BY created_at DESC LIMIT :limit"
        
        result = await session.execute(text(query), params)
        rows = result.fetchall()
        
        return {
            "events": [
                {
                    "id": str(r[0]),
                    "event_type": r[1],
                    "payload": json.loads(r[2]) if isinstance(r[2], str) else r[2],
                    "status": r[3],
                    "attempts": r[4],
                    "last_attempt_at": r[5].isoformat() if r[5] else None,
                    "delivered_at": r[6].isoformat() if r[6] else None,
                    "error_message": r[7],
                    "created_at": r[8].isoformat() if r[8] else None,
                }
                for r in rows
            ]
        }


@router.post("/clients/{client_id}/webhook/events/{event_id}/retry")
async def retry_webhook_event(
    client_id: str,
    event_id: str,
    authorization: str = Header(...)
):
    """Retry delivery of a failed webhook event"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        # Verify ownership
        owner_check = await session.execute(
            text("SELECT id FROM oauth_clients WHERE client_id = :client_id AND user_id = :uid"),
            {"client_id": client_id, "uid": uid}
        )
        if not owner_check.fetchone():
            raise HTTPException(status_code=404, detail="OAuth client not found")
        
        # Reset event status to pending
        result = await session.execute(
            text("""UPDATE oauth_webhook_events
                   SET status = 'pending'
                   WHERE id = :event_id AND client_id = :client_id
                   RETURNING id"""),
            {"event_id": event_id, "client_id": client_id}
        )
        row = result.fetchone()
        await session.commit()
        
        if not row:
            raise HTTPException(status_code=404, detail="Webhook event not found")
        
        # Attempt delivery
        success = await webhook_service.deliver_webhook(event_id)
        
        return {
            "event_id": event_id,
            "retry_successful": success,
            "message": "Webhook delivered successfully" if success else "Webhook delivery failed"
        }


@router.post("/clients/{client_id}/webhook/test")
async def test_webhook(client_id: str, authorization: str = Header(...)):
    """Send a test webhook event"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        # Verify ownership and get webhook config
        result = await session.execute(
            text("""SELECT webhook_url, webhook_secret FROM oauth_clients
                   WHERE client_id = :client_id AND user_id = :uid"""),
            {"client_id": client_id, "uid": uid}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="OAuth client not found")
        
        if not row[0]:
            raise HTTPException(status_code=400, detail="No webhook URL configured")
    
    # Queue test event
    event_id = await webhook_service.queue_webhook_event(
        client_id=client_id,
        event_type="test.webhook",
        data={
            "message": "This is a test webhook event",
            "client_id": client_id
        }
    )
    
    return {
        "event_id": event_id,
        "message": "Test webhook event queued for delivery"
    }
