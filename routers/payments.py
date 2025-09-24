import os
import json
import logging
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException, Request

logger = logging.getLogger("backend.payments")

router = APIRouter(prefix="/api/payments", tags=["payments"])  # /api/payments/*

# Firebase Admin (optional auth verification)
try:
    import firebase_admin
    from firebase_admin import auth as admin_auth
    _FB_AVAILABLE = True
except Exception:
    firebase_admin = None  # type: ignore
    admin_auth = None  # type: ignore
    _FB_AVAILABLE = False

import urllib.request
import urllib.error


def _verify_id_token_from_header(request: Request) -> Optional[str]:
    """Verify Firebase ID token from Authorization: Bearer <token>. Return uid or None.
    If Firebase Admin isn't available, returns None.
    """
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


@router.post("/dodo/checkout")
async def create_dodo_checkout(request: Request, payload: Dict):
    """Create a Dodo Payments checkout session dynamically (server-side).

    Expected body example:
    {
      "product_id": "your_product_id",
      "quantity": 1,
      "plan": "pro"  # optional, default 'pro'
    }

    The server will attach metadata with the authenticated user's uid when possible.
    If Authorization Bearer Firebase ID token is provided, it will be used to derive uid.
    Otherwise, the caller may provide payload["uid"] as a fallback.
    """
    dodo_url = os.getenv("DODO_CHECKOUT_CREATE_URL")
    dodo_api_key = os.getenv("DODO_API_KEY")
    if not dodo_url or not dodo_api_key:
        logger.error("Dodo API not configured: missing DODO_CHECKOUT_CREATE_URL or DODO_API_KEY")
        raise HTTPException(status_code=500, detail="Payments not configured on server")

    # Derive user UID
    uid = _verify_id_token_from_header(request)
    if not uid:
        uid = str(payload.get("uid") or "").strip()
    if not uid:
        logger.warning("[dodo-checkout] missing uid; rejecting")
        raise HTTPException(status_code=400, detail="Missing uid for checkout")

    product_id = str(payload.get("product_id") or payload.get("productId") or "").strip()
    if not product_id:
        raise HTTPException(status_code=400, detail="Missing product_id")
    try:
        quantity = int(payload.get("quantity") or 1)
        if quantity <= 0:
            quantity = 1
    except Exception:
        quantity = 1
    plan = str(payload.get("plan") or "pro").strip() or "pro"

    # Determine the return URL for post-payment redirection
    return_url = (
        str(payload.get("return_url") or "").strip()
        or str(payload.get("redirect_url") or "").strip()
        or os.getenv("RETURN_URL")
        or os.getenv("CHECKOUT_REDIRECT_URL")
        or ""
    )

    body = {
        "product_cart": [{"product_id": product_id, "quantity": quantity}],
        "metadata": {
            "user_uid": uid,
            "plan": plan,
        },
        # provider requires 'return_url' for redirect after checkout completion
        "return_url": return_url,
    }

    # Make request to Dodo API
    try:
        # Prepare auth headers (supports either Authorization: Bearer <key> or custom header via DODO_AUTH_HEADER)
        auth_header = os.getenv("DODO_AUTH_HEADER", "Authorization")
        auth_scheme = os.getenv("DODO_AUTH_SCHEME", "Bearer")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": os.getenv("OUTBOUND_USER_AGENT", "CleanEnroll/1.0 payments (+https://cleanenroll.com)"),
        }
        if auth_header.lower() == "authorization":
            headers["Authorization"] = f"{auth_scheme} {dodo_api_key}".strip()
        else:
            headers[auth_header] = dodo_api_key

        logger.debug("[dodo-checkout] POST %s auth_header=%s scheme=%s", dodo_url, auth_header, auth_scheme)

        req = urllib.request.Request(
            url=dodo_url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(resp_body)
            except Exception:
                data = {"raw": resp_body}
            if resp.status not in (200, 201):
                logger.warning("[dodo-checkout] API status=%s body=%s", resp.status, resp_body[:500])
                raise HTTPException(status_code=502, detail="Failed to create checkout")
            logger.info("[dodo-checkout] created session for uid=%s product=%s qty=%s", uid, product_id, quantity)
            return data
    except HTTPException:
        raise
    except urllib.error.HTTPError as he:  # type: ignore[attr-defined]
        try:
            err_body = he.read().decode("utf-8", errors="replace")  # type: ignore[call-arg]
        except Exception:
            err_body = ""
        logger.warning("[dodo-checkout] HTTPError status=%s body=%s", getattr(he, 'code', 'n/a'), err_body[:500])
        raise HTTPException(status_code=502, detail=f"Checkout provider error ({getattr(he, 'code', 'n/a')})")
    except urllib.error.URLError as ue:  # type: ignore[attr-defined]
        logger.warning("[dodo-checkout] URLError reason=%s", getattr(ue, 'reason', ue))
        raise HTTPException(status_code=502, detail="Checkout provider unreachable")
    except Exception as e:
        logger.exception("[dodo-checkout] request failed")
        raise HTTPException(status_code=502, detail="Checkout provider error")
