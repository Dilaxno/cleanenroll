"""
Billing endpoints - user billing information and subscription management
All data stored in Neon database (users.plan_details, users.subscription_id)
"""
import os
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from sqlalchemy import text

logger = logging.getLogger("backend.billing")

router = APIRouter(prefix="/api/billing", tags=["billing"])

# Firebase Admin for auth verification
try:
    import firebase_admin
    from firebase_admin import auth as admin_auth
    _FB_AVAILABLE = True
except Exception:
    firebase_admin = None
    admin_auth = None
    _FB_AVAILABLE = False

# Neon database
try:
    from db.database import async_session_maker
except Exception:
    from ..db.database import async_session_maker


def _verify_id_token_from_header(request: Request) -> Optional[str]:
    """Verify Firebase ID token from Authorization: Bearer <token>. Return uid or None."""
    if not _FB_AVAILABLE:
        return None
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authz or not authz.lower().startswith("bearer "):
        return None
    token = authz.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        decoded = admin_auth.verify_id_token(token)
        return decoded.get("uid")
    except Exception:
        return None


@router.get("/info")
async def get_billing_info(request: Request):
    """
    Get user billing information from Neon database.
    Returns plan, subscription_id, and plan_details (billing info).
    """
    uid = _verify_id_token_from_header(request)
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                text("""
                    SELECT plan, subscription_id, plan_details, last_payment_id
                    FROM users 
                    WHERE uid = :uid
                    LIMIT 1
                """),
                {"uid": uid}
            )
            row = result.fetchone()
            
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            
            plan = row[0] or "free"
            subscription_id = row[1]
            plan_details = row[2] if row[2] else {}
            last_payment_id = row[3]
            
            # Extract billing info from plan_details
            billing_info = {
                "plan": plan,
                "subscriptionId": subscription_id,
                "lastPaymentId": last_payment_id,
                "nextBillingAt": plan_details.get("nextBillingAt"),
                "cancelAtPeriodEnd": plan_details.get("cancelAtPeriodEnd", False),
                "status": plan_details.get("status", "active" if plan != "free" else "inactive"),
                "currency": plan_details.get("currency", "USD"),
                "price": plan_details.get("price"),
                "interval": plan_details.get("interval", "month"),
                "paymentMethod": plan_details.get("paymentMethod"),
            }
            
            # Add portal URL from environment
            billing_info["portalUrl"] = (
                os.getenv("DODO_MANAGE_SUBSCRIPTION_URL") 
                or os.getenv("FRONTEND_URL", "https://cleanenroll.com").rstrip("/") + "/billing/portal"
            )
            
            return {"billing": billing_info}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to fetch billing info for uid=%s", uid)
        raise HTTPException(status_code=500, detail=f"Failed to fetch billing info: {str(e)}")


@router.get("/portal-url")
async def get_portal_url():
    """Get the billing portal URL from environment configuration."""
    portal_url = (
        os.getenv("DODO_MANAGE_SUBSCRIPTION_URL") 
        or os.getenv("FRONTEND_URL", "https://cleanenroll.com").rstrip("/") + "/billing/portal"
    )
    return {"portalUrl": portal_url}
