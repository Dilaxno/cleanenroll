import os
import json
import logging
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException, Request

# Email utils for notifications
try:
    from utils.email import render_email, send_email_html  # type: ignore
except Exception:
    from utils.email import render_email, send_email_html  # type: ignore

logger = logging.getLogger("backend.payments")

router = APIRouter(prefix="/api/payments", tags=["payments"])  # /api/payments/*

# Neon (PostgreSQL) for user plan/email updates
try:
    from db.database import async_session_maker  # type: ignore
except Exception:
    from ..db.database import async_session_maker  # type: ignore

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
import time
try:
    from standardwebhooks import Webhook  # type: ignore
    _STDWEBHOOKS_AVAILABLE = True
except Exception:
    Webhook = None  # type: ignore
    _STDWEBHOOKS_AVAILABLE = False

# Firestore removed - all user data now stored in Neon database

# Dodo Payments Python SDK (async)
try:
    from dodopayments import AsyncDodoPayments  # type: ignore
    _DODO_SDK_AVAILABLE = True
except Exception:
    AsyncDodoPayments = None  # type: ignore
    _DODO_SDK_AVAILABLE = False

def _dodo_environment() -> str:
    """Return 'test_mode' or 'live_mode' based on env flags."""
    env = (os.getenv("DODO_ENV") or os.getenv("DODO_ENVIRONMENT") or "test_mode").strip().lower()
    if env in ("live", "live_mode", "production", "prod"):
        return "live_mode"
    return "test_mode"


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


async def _update_user_billing(uid: str, updates: Dict):
    """
    Update user billing information in Neon plan_details JSONB column.
    Merges new updates with existing plan_details data.
    """
    if not uid or not updates:
        return
    
    try:
        from sqlalchemy import text as _text
        async with async_session_maker() as session:
            # Fetch current plan_details
            result = await session.execute(
                _text("SELECT plan_details FROM users WHERE uid = :uid"),
                {"uid": uid}
            )
            row = result.fetchone()
            
            # Merge with existing data
            current_details = {}
            if row and row[0]:
                current_details = row[0] if isinstance(row[0], dict) else {}
            
            # Update with new data
            current_details.update(updates)
            
            # Save back to database
            await session.execute(
                _text("UPDATE users SET plan_details = :details, updated_at = NOW() WHERE uid = :uid"),
                {"details": json.dumps(current_details), "uid": uid}
            )
            await session.commit()
            logger.info('[payments] updated billing for uid=%s keys=%s', uid, list(updates.keys()))
    except Exception:
        logger.exception('[payments] failed to update billing for uid=%s', uid)


async def _set_user_plan(uid: str, plan: str):
    if not uid:
        return
    try:
        async with async_session_maker() as session:
            await session.execute(
                "UPDATE users SET plan = :plan, updated_at = NOW() WHERE uid = :uid",
                {"plan": plan, "uid": uid},
            )
            await session.commit()
    except Exception:
        logger.exception('[payments] failed to set user plan uid=%s', uid)


async def _get_user_email(uid: str) -> Optional[str]:
    if not uid:
        return None
    try:
        async with async_session_maker() as session:
            res = await session.execute("SELECT email FROM users WHERE uid = :uid", {"uid": uid})
            row = res.first()
            if row and row[0] and isinstance(row[0], str) and '@' in row[0]:
                return row[0].strip()
    except Exception:
        logger.warning('[payments] failed to get user email for uid=%s', uid)
    return None


def _send_billing_email(to_email: str, subject: str, intro: str, content_html: Optional[str] = None, cta_label: Optional[str] = None, cta_url: Optional[str] = None, title: Optional[str] = None):
    """Render and send a branded billing email from billing@cleanenroll.com using base.html template."""
    try:
        from datetime import datetime
        html = render_email('base.html', {
            'subject': subject,
            'preheader': intro,
            'title': title or subject,  # Use custom title or fallback to subject
            'intro': intro,
            'content_html': content_html or '',
            'cta_label': cta_label,
            'cta_url': cta_url,
            'year': datetime.now().year,
        })
        send_email_html(to_email, subject, html, from_addr='billing@cleanenroll.com')
        logger.info('[payments] sent billing email to %s with subject: %s', to_email, subject)
    except Exception:
        logger.exception('[payments] failed to send billing email to %s', to_email)


def _forward_dodo_event(event_type: str, uid: str) -> None:
    """Optional best-effort forwarder for internal auditing/bridging.
    Configure DODO_FORWARD_WEBHOOK_URL to enable. No-ops when unset.
    """
    url = os.getenv('DODO_FORWARD_WEBHOOK_URL') or ''
    if not url:
        return
    try:
        body = {
            'type': event_type,
            'data': {'metadata': {'user_uid': uid}},
        }
        req = urllib.request.Request(
            url=url,
            data=json.dumps(body).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=10):  # type: ignore
            pass
    except Exception:
        logger.warning('[payments] forward_dodo_event failed', exc_info=True)


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
    
    # Checkout page customization: theme can be 'dark' | 'light' | 'system'
    _theme = (os.getenv("DODO_CHECKOUT_THEME") or "dark").strip().lower()
    if _theme not in ("dark", "light", "system"):
        _theme = "dark"
    _customization = {
        "theme": _theme,
        "show_order_details": True,
        "show_on_demand_tag": False,
    }
    
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
        "customization": _customization,
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


@router.post("/dodo/create-session")
async def create_dodo_dynamic_session(request: Request, payload: Dict):
    """Create a dynamic Dodo Payments checkout session for a specific submission.

    Expected body example:
    {
      "form_id": "form_123",
      "submission_id": "resp_abc",
      "amount_cents": 1234,           # required (>0)
      "currency": "USD",             # optional, default USD
      "description": "Payment for X",# optional
      "return_url": "https://...",   # optional
      "cancel_url": "https://..."    # optional
    }
    The server will attach metadata with form_id and submission_id.
    If Authorization Bearer Firebase ID token is provided, we also include user_uid in metadata when available.
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")

    dodo_url = os.getenv("DODO_DYNAMIC_CHECKOUT_URL") or os.getenv("DODO_CHECKOUT_CREATE_URL")
    dodo_api_key = os.getenv("DODO_API_KEY") or os.getenv("DODO_PAYMENTS_API_KEY")
    if not dodo_url or not dodo_api_key:
        logger.error("Dodo API not configured: missing DODO_DYNAMIC_CHECKOUT_URL/DODO_CHECKOUT_CREATE_URL or DODO_API_KEY/DODO_PAYMENTS_API_KEY")
        raise HTTPException(status_code=500, detail="Payments not configured on server")

    # Validate amount
    try:
        amount_cents = int(payload.get("amount_cents"))
    except Exception:
        amount_cents = 0
    if amount_cents <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount_cents")

    currency = str(payload.get("currency") or "USD").upper()
    description = (payload.get("description") or "").strip() or None
    form_id = (payload.get("form_id") or payload.get("formId") or "").strip()
    submission_id = (payload.get("submission_id") or payload.get("submissionId") or "").strip()
    if not form_id or not submission_id:
        raise HTTPException(status_code=400, detail="Missing form_id or submission_id")

    # Derive user UID from Firebase token when available (best-effort)
    uid = _verify_id_token_from_header(request)

    # Determine the return/cancel URLs
    default_return = os.getenv("RETURN_URL") or os.getenv("CHECKOUT_REDIRECT_URL") or ""
    return_url = (payload.get("return_url") or default_return or "").strip()
    cancel_url = (payload.get("cancel_url") or default_return or "").strip()
    
    # Checkout page customization: theme can be 'dark' | 'light' | 'system'
    _theme = (os.getenv("DODO_CHECKOUT_THEME") or "dark").strip().lower()
    if _theme not in ("dark", "light", "system"):
        _theme = "dark"
    _customization = {
        "theme": _theme,
        "show_order_details": True,
        "show_on_demand_tag": False,
    }
    
    # Build product cart with a single dynamic item
    product_cart = [{
        "name": description or f"Payment for form {form_id}",
        "unit_amount_cents": amount_cents,
        "quantity": 1,
    }]

    body = {
        "product_cart": product_cart,
        "currency": currency,
        "metadata": {
            "form_id": form_id,
            "submission_id": submission_id,
            **({"user_uid": uid} if uid else {}),
        },
        "customization": _customization,
        # Most providers use these for post-payment navigation
        "return_url": return_url,
        "cancel_url": cancel_url,
    }

    # Make request to Dodo API
    try:
        # Prepare auth headers
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

        logger.debug("[dodo-session] POST %s auth_header=%s scheme=%s", dodo_url, auth_header, auth_scheme)

        def _post(url: str, payload: Dict) -> Dict:
            req = urllib.request.Request(
                url=url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=20) as resp:  # type: ignore
                resp_body = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(resp_body)
                except Exception:
                    data = {"raw": resp_body}
                if resp.status not in (200, 201):
                    logger.warning("[dodo-session] API status=%s body=%s", resp.status, resp_body[:500])
                    raise HTTPException(status_code=502, detail="Failed to create checkout session")
                return data

        # Attempt dynamic session first
        try:
            data = _post(dodo_url, body)
            logger.info("[dodo-session] created dynamic session form=%s submission=%s uid=%s amount=%s %s", form_id, submission_id, uid or "", amount_cents, currency)
            return data
        except urllib.error.HTTPError as he1:  # type: ignore[attr-defined]
            # Read error body to detect provider requiring product_id
            try:
                err_txt = he1.read().decode("utf-8", errors="replace")  # type: ignore[call-arg]
            except Exception:
                err_txt = ""
            code = getattr(he1, 'code', None)
            needs_product = (code == 422) and ("missing field `product_id`" in (err_txt or ""))
            fallback_pid = os.getenv("DODO_FALLBACK_PRODUCT_ID") or os.getenv("DODO_PRODUCT_ID")
            if needs_product and fallback_pid:
                logger.info("[dodo-session] provider requires product_id, retrying with fallback product_id=%s", fallback_pid)
                fallback_body = {
                    "product_cart": [{"product_id": fallback_pid, "quantity": 1}],
                    "metadata": {"form_id": form_id, "submission_id": submission_id, **({"user_uid": uid} if uid else {}), "desired_amount_cents": amount_cents, "desired_currency": currency},
                    "return_url": return_url,
                    "cancel_url": cancel_url,
                }
                data = _post(dodo_url, fallback_body)
                logger.info("[dodo-session] created product-based session form=%s submission=%s uid=%s product_id=%s", form_id, submission_id, uid or "", fallback_pid)
                return data
            if needs_product and not fallback_pid:
                logger.error("[dodo-session] dynamic checkout endpoint requires product_id but no fallback configured")
                raise HTTPException(status_code=400, detail=(
                    "Payments provider endpoint requires a product_id. Configure DODO_DYNAMIC_CHECKOUT_URL to the dynamic endpoint that accepts unit_amount_cents, or set DODO_FALLBACK_PRODUCT_ID to use a fixed product checkout."
                ))
            # Unknown error -> rethrow
            raise he1
    except HTTPException:
        raise
    except urllib.error.HTTPError as he:  # type: ignore[attr-defined]
        try:
            err_body = he.read().decode("utf-8", errors="replace")  # type: ignore[call-arg]
        except Exception:
            err_body = ""
        logger.warning("[dodo-session] HTTPError status=%s body=%s", getattr(he, 'code', 'n/a'), err_body[:500])
        raise HTTPException(status_code=502, detail=f"Checkout provider error ({getattr(he, 'code', 'n/a')})")
    except urllib.error.URLError as ue:  # type: ignore[attr-defined]
        logger.warning("[dodo-session] URLError reason=%s", getattr(ue, 'reason', ue))
        raise HTTPException(status_code=502, detail="Checkout provider unreachable")
    except Exception:
        logger.exception("[dodo-session] request failed")
        raise HTTPException(status_code=502, detail="Checkout provider error")

@router.post("/dodo/form-checkout")
async def dodo_form_checkout(payload: Dict):
    """
    Create a hosted checkout session for a form submission using a pay_what_you_want product.
    Requirements:
    - Env DODO_PWYW_PRODUCT_ID (or DODO_PRODUCT_ID) is a one-time price product with pay_what_you_want enabled.
    - Currency amounts are in the lowest denomination (e.g., cents for USD).
    Body:
    {
      "form_id": "form_123",              // recommended
      "submission_id": "sub_abc",         // recommended
      "owner_id": "uid_123",              // optional; resolved from DB if omitted
      "amount_cents": 2500,               // required, > 0
      "currency": "USD",                  // optional, defaults to USD
      "customer": { "email": "...", "name": "..." }, // optional
      "return_url": "https://...",        // optional (falls back to env)
      "allowed_payment_method_types": ["credit","debit","apple_pay","google_pay"] // optional
    }
    Response: { id, url, payment_status }
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")

    # Validate amount (smallest unit)
    try:
        amount_cents = int(payload.get("amount_cents"))
    except Exception:
        amount_cents = 0
    if amount_cents <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount_cents")

    # Identify the context
    form_id = (payload.get("form_id") or payload.get("formId") or "").strip()
    submission_id = (payload.get("submission_id") or payload.get("submissionId") or "").strip()
    owner_id = (payload.get("owner_id") or payload.get("ownerId") or "").strip()
    if not form_id and not submission_id:
        raise HTTPException(status_code=400, detail="Provide form_id or submission_id")

    currency = (payload.get("currency") or "USD").upper().strip()

    # Checkout customization
    theme = (os.getenv("DODO_CHECKOUT_THEME") or "dark").strip().lower()
    if theme not in ("dark", "light", "system"):
        theme = "dark"

    return_url = (payload.get("return_url") or os.getenv("RETURN_URL") or os.getenv("CHECKOUT_REDIRECT_URL") or "").strip()

    # Customer (optional)
    customer = payload.get("customer") or {}
    customer_email = (customer.get("email") or "").strip() if isinstance(customer, dict) else ""
    customer_name = (customer.get("name") or "").strip() if isinstance(customer, dict) else ""

    # Pay-what-you-want product
    pwyw_product_id = os.getenv("DODO_PWYW_PRODUCT_ID") or os.getenv("DODO_PRODUCT_ID") or ""
    if not pwyw_product_id:
        raise HTTPException(status_code=500, detail="Payments not configured (DODO_PWYW_PRODUCT_ID missing)")

    # Payment methods (ensure credit & debit fallback)
    allowed_methods = payload.get("allowed_payment_method_types") or ["credit", "debit", "apple_pay", "google_pay"]
    if "credit" not in allowed_methods:
        allowed_methods.append("credit")
    if "debit" not in allowed_methods:
        allowed_methods.append("debit")

    token = os.getenv("DODO_PAYMENTS_API_KEY") or os.getenv("DODO_API_KEY")
    if not (_DODO_SDK_AVAILABLE and token):
        raise HTTPException(status_code=500, detail="Payments SDK unavailable or API key missing")

    try:
        # Use official SDK (Context7 reference: https://github.com/dodopayments/dodopayments-python)
        async with AsyncDodoPayments(bearer_token=token, environment=_dodo_environment()) as client:  # type: ignore
            req = {
                "product_cart": [
                    {
                        "product_id": pwyw_product_id,
                        "quantity": 1,
                        # amount is respected when pay_what_you_want is enabled for one-time product
                        "amount": amount_cents,
                    }
                ],
                "billing_currency": currency,
                "allowed_payment_method_types": allowed_methods,
                "metadata": {
                    "owner_id": owner_id,
                    "form_id": form_id,
                    "submission_id": submission_id,
                },
                "return_url": return_url,
                "customization": {
                    "theme": theme,
                    "show_order_details": True,
                    "show_on_demand_tag": False,
                },
                "show_saved_payment_methods": False,
                "confirm": False,
            }
            if customer_email:
                req["customer"] = {"email": customer_email, **({"name": customer_name} if customer_name else {})}

            session = await client.checkout_sessions.create(**req)  # type: ignore[arg-type]
            # Extract common fields safely for redirect
            session_id = getattr(session, "id", None) or getattr(session, "session_id", None) or None
            session_url = getattr(session, "url", None) or None
            payment_status = getattr(session, "payment_status", None) or None
            return {"id": session_id, "url": session_url, "payment_status": payment_status}
    except HTTPException:
        raise
    except Exception:
        logger.exception("[dodo-form-checkout] failed to create checkout session")
        raise HTTPException(status_code=502, detail="Checkout provider error")

async def _record_owner_transaction(data: Dict, event_type: str) -> None:
    """
    Upsert a one-time payment into owner_transactions for the Earnings dashboard.
    Assumes amounts in the smallest currency unit (e.g., cents for USD).
    """
    try:
        meta = data.get("metadata") or {}
        form_id = meta.get("form_id") or meta.get("formId")
        submission_id = meta.get("submission_id") or meta.get("submissionId")

        # Identify payment fields
        payment_id = data.get("payment_id") or data.get("id")
        status = "succeeded" if event_type == "payment.succeeded" else "failed"
        currency = (data.get("currency") or "USD").upper()

        # Amounts
        total_amount = None
        for k in ("total_amount", "amount", "amount_cents", "total"):
            v = data.get(k)
            if isinstance(v, (int, float)):
                total_amount = int(v)
                break
        total_amount = int(total_amount or 0)

        fee_amount = 0
        fees = data.get("fees")
        if isinstance(fees, dict):
            fv = fees.get("total") or fees.get("fee_amount")
            if isinstance(fv, (int, float)):
                fee_amount = int(fv)
        elif isinstance(data.get("fee"), (int, float)):
            fee_amount = int(data.get("fee"))
        net_amount = max(total_amount - fee_amount, 0)

        # Customer email
        customer_email = None
        cust = data.get("customer") or {}
        if isinstance(cust, dict):
            ce = cust.get("email")
            if isinstance(ce, str):
                customer_email = ce
        if not customer_email and isinstance(data.get("customer_email"), str):
            customer_email = data.get("customer_email")

        # Payment method type
        payment_method_type = data.get("payment_method_type")
        if not payment_method_type:
            pm = data.get("payment_method") or {}
            if isinstance(pm, dict):
                payment_method_type = pm.get("type")

        if not payment_id:
            logger.warning("[owner_txn] missing payment_id; skipping ledger write")
            return

        # Resolve owner_id via DB
        from sqlalchemy import text as _text  # local import to avoid global dependency
        resolved_owner_id = None
        async with async_session_maker() as session:
            try:
                if not resolved_owner_id and submission_id:
                    res = await session.execute(
                        _text("SELECT form_owner_id, form_id FROM submissions WHERE id = :sid"),
                        {"sid": str(submission_id)},
                    )
                    row = res.first()
                    if row:
                        resolved_owner_id = row[0]
                        if not form_id:
                            form_id = row[1]
                if not resolved_owner_id and form_id:
                    res = await session.execute(
                        _text("SELECT user_id FROM forms WHERE id = :fid"),
                        {"fid": str(form_id)},
                    )
                    row = res.first()
                    if row:
                        resolved_owner_id = row[0]
            except Exception:
                logger.exception("[owner_txn] failed to resolve owner for form_id=%s submission_id=%s", form_id, submission_id)

            try:
                await session.execute(
                    _text("""
                        INSERT INTO owner_transactions
                            (payment_id, owner_id, form_id, submission_id, status, total_amount, currency, fee_amount, net_amount, customer_email, payment_method_type, created_at, updated_at)
                        VALUES
                            (:payment_id, :owner_id, :form_id, :submission_id, :status, :total_amount, :currency, :fee_amount, :net_amount, :customer_email, :payment_method_type, NOW(), NOW())
                        ON CONFLICT (payment_id) DO UPDATE SET
                            status = EXCLUDED.status,
                            total_amount = EXCLUDED.total_amount,
                            currency = EXCLUDED.currency,
                            fee_amount = EXCLUDED.fee_amount,
                            net_amount = EXCLUDED.net_amount,
                            customer_email = EXCLUDED.customer_email,
                            payment_method_type = EXCLUDED.payment_method_type,
                            owner_id = COALESCE(owner_transactions.owner_id, EXCLUDED.owner_id),
                            form_id = COALESCE(owner_transactions.form_id, EXCLUDED.form_id),
                            submission_id = COALESCE(owner_transactions.submission_id, EXCLUDED.submission_id),
                            updated_at = NOW()
                    """),
                    {
                        "payment_id": str(payment_id),
                        "owner_id": resolved_owner_id,
                        "form_id": form_id,
                        "submission_id": submission_id,
                        "status": status,
                        "total_amount": int(total_amount),
                        "currency": currency,
                        "fee_amount": int(fee_amount),
                        "net_amount": int(net_amount),
                        "customer_email": customer_email,
                        "payment_method_type": payment_method_type,
                    },
                )
                await session.commit()
                logger.info(
                    "[owner_txn] upserted payment_id=%s status=%s gross=%s %s net=%s",
                    payment_id, status, total_amount, currency, net_amount
                )
            except Exception:
                await session.rollback()
                logger.exception("[owner_txn] failed to upsert payment_id=%s", payment_id)
    except Exception:
        logger.exception("[owner_txn] unexpected error")

async def _process_dodo_event(payload: Dict):
    """Apply Dodo event to local state (plan/billing) and send emails.
    Expects a dict payload like the provider's JSON body.
    """
    try:
        event_type = str(payload.get('type') or payload.get('event') or '').strip().lower()
        data = payload.get('data') or payload.get('object') or {}
        meta = data.get('metadata') or {}
        uid = meta.get('user_uid') or meta.get('uid') or data.get('user_uid') or ''
        next_billing = data.get('current_period_end') or data.get('next_billing_at') or data.get('renews_at')
        price_amount = data.get('amount') or data.get('price') or None
        currency = (data.get('currency') or 'USD').upper()
        # Payment method details (if present)
        payment_method = data.get('payment_method') or data.get('paymentMethod') or {}

        # Normalize timestamp from seconds or ISO
        def normalize_ts(v):
            if not v:
                return None
            try:
                if isinstance(v, (int, float)):
                    return int(v) * 1000  # ms for frontend convenience
                s = str(v)
                from datetime import datetime
                return datetime.fromisoformat(s.replace('Z','+00:00')).isoformat()
            except Exception:
                return v

        if event_type == 'subscription.cancelled':
            # Immediately set plan to free and clear billing flags
            if uid:
                await _set_user_plan(uid, 'free')
                # Clear subscription_id from database since subscription is cancelled
                try:
                    async with async_session_maker() as session:
                        await session.execute(
                            "UPDATE users SET subscription_id = NULL, updated_at = NOW() WHERE uid = :uid",
                            {"uid": uid}
                        )
                        await session.commit()
                    logger.info('[payments] cleared subscription_id for cancelled subscription uid=%s', uid)
                except Exception:
                    logger.exception('[payments] failed to clear subscription_id for uid=%s', uid)
                await _update_user_billing(uid, {
                    'nextBillingAt': None,
                    'cancelAtPeriodEnd': False,
                    'status': 'cancelled',
                })
                # Notify user about cancellation (best-effort)
                try:
                    email = await _get_user_email(uid)
                    if email:
                        portal = os.getenv('DODO_MANAGE_SUBSCRIPTION_URL') or (os.getenv('FRONTEND_URL', 'https://cleanenroll.com').rstrip('/') + '/billing/portal')
                        subject = 'Your CleanEnroll subscription was canceled'
                        intro = 'Your subscription has been canceled. You will no longer be charged.'
                        _send_billing_email(email, subject, intro, cta_label='Manage Billing', cta_url=portal)
                except Exception:
                    logger.exception('[payments] failed to send cancellation email for uid=%s', uid)
        elif event_type in ('subscription.renewed', 'subscription.created', 'invoice.paid'):
            if uid:
                await _set_user_plan(uid, 'pro')
                # Extract subscription_id from webhook payload
                subscription_id = (
                    data.get('subscription_id')
                    or data.get('subscription', {}).get('id')
                    or meta.get('subscription_id')
                    or data.get('id')  # fallback to data.id if it's the subscription object itself
                )
                # Store subscription_id in Neon DB for future cancellation/management
                if subscription_id:
                    try:
                        async with async_session_maker() as session:
                            await session.execute(
                                "UPDATE users SET subscription_id = :sub_id, updated_at = NOW() WHERE uid = :uid",
                                {"sub_id": str(subscription_id), "uid": uid}
                            )
                            await session.commit()
                        logger.info('[payments] stored subscription_id=%s for uid=%s', subscription_id, uid)
                    except Exception:
                        logger.exception('[payments] failed to store subscription_id for uid=%s', uid)
                # Best-effort payment identifier extraction (depends on provider payload)
                payment_id = (
                    data.get('payment_id')
                    or data.get('invoice_id')
                    or data.get('id')
                    or (data.get('payment') or {}).get('id')
                    or (data.get('invoice') or {}).get('id')
                )
                
                # Check if this is the first time user becomes Pro (track member_since)
                billing_updates = {
                    'nextBillingAt': normalize_ts(next_billing),
                    'cancelAtPeriodEnd': False,
                    'currency': currency,
                    'price': price_amount if isinstance(price_amount, (int, float)) else None,
                    'status': 'active',
                    'paymentMethod': payment_method if isinstance(payment_method, dict) else None,
                    **({'lastPaymentId': payment_id} if payment_id else {}),
                }
                
                # For subscription.created, set member_since timestamp
                member_since_ts = None
                if event_type == 'subscription.created':
                    import time
                    member_since_ts = int(time.time() * 1000)  # ms timestamp
                    billing_updates['memberSince'] = member_since_ts
                    logger.info('[payments] setting memberSince for new subscription uid=%s', uid)
                
                # Store in plan_details JSONB
                await _update_user_billing(uid, billing_updates)
                
                # Also store next_billing_at and member_since in dedicated columns
                try:
                    from datetime import datetime
                    async with async_session_maker() as session:
                        # Convert next_billing to proper timestamp for database
                        next_billing_db = None
                        if next_billing:
                            if isinstance(next_billing, (int, float)):
                                next_billing_db = datetime.fromtimestamp(int(next_billing))
                            else:
                                try:
                                    next_billing_db = datetime.fromisoformat(str(next_billing).replace('Z', '+00:00'))
                                except Exception:
                                    pass
                        
                        # Convert member_since to proper timestamp
                        member_since_db = None
                        if member_since_ts:
                            member_since_db = datetime.fromtimestamp(member_since_ts / 1000.0)
                        
                        # Update columns
                        if next_billing_db:
                            await session.execute(
                                "UPDATE users SET next_billing_at = :next_billing, updated_at = NOW() WHERE uid = :uid",
                                {"next_billing": next_billing_db, "uid": uid}
                            )
                        
                        # Only set member_since if it's a new subscription (don't overwrite existing)
                        if member_since_db and event_type == 'subscription.created':
                            await session.execute(
                                "UPDATE users SET member_since = :member_since WHERE uid = :uid AND member_since IS NULL",
                                {"member_since": member_since_db, "uid": uid}
                            )
                        
                        await session.commit()
                        logger.info('[payments] updated billing columns for uid=%s next_billing=%s member_since=%s', 
                                  uid, next_billing_db, member_since_db)
                except Exception:
                    logger.exception('[payments] failed to update billing columns for uid=%s', uid)
                # Notify user about successful upgrade/renewal (best-effort)
                try:
                    email = await _get_user_email(uid)
                    if email:
                        portal = os.getenv('DODO_MANAGE_SUBSCRIPTION_URL') or (os.getenv('FRONTEND_URL', 'https://cleanenroll.com').rstrip('/') + '/billing/portal')
                        
                        # Differentiate between new subscription (upgrade) and renewal
                        is_new_subscription = event_type == 'subscription.created'
                        
                        if is_new_subscription:
                            # Thank you email for new upgrades
                            subject = 'Thank you for upgrading to CleanEnroll Pro! 🎉'
                            title = 'Welcome to CleanEnroll Pro!'
                            intro = 'Thank you for upgrading your account! We\'re thrilled to have you as a Pro member.'
                            content_parts = [
                                '<p style="margin:0 0 12px 0;color:#c7c7c7">Your upgrade unlocks powerful features to help you collect more submissions and grow your business:</p>',
                                '<ul style="margin:0 0 16px 0;color:#c7c7c7;padding-left:20px;">',
                                '<li style="margin-bottom:8px;">Unlimited forms and submissions</li>',
                                '<li style="margin-bottom:8px;">Advanced analytics and insights</li>',
                                '<li style="margin-bottom:8px;">Priority support</li>',
                                '<li style="margin-bottom:8px;">Custom branding options</li>',
                                '<li>And much more!</li>',
                                '</ul>',
                            ]
                        else:
                            # Confirmation email for renewals
                            subject = 'Your CleanEnroll subscription has been renewed'
                            title = 'Subscription Renewed'
                            intro = 'Your CleanEnroll Pro subscription has been successfully renewed.'
                            content_parts = [
                                '<p style="margin:0 0 12px 0;color:#c7c7c7">Thank you for continuing to use CleanEnroll Pro!</p>',
                            ]
                        
                        # Add payment amount info
                        if isinstance(price_amount, (int, float)) and currency:
                            try:
                                amt = float(price_amount) / (100.0 if price_amount and price_amount > 50 else 1.0)
                                content_parts.append(f'<p style="margin:16px 0 0 0;color:#c7c7c7">Amount charged: <strong style="color:#7ED957">${amt:.2f} {currency}</strong></p>')
                            except Exception:
                                pass
                        
                        # Add next billing date if available
                        if next_billing:
                            try:
                                from datetime import datetime
                                if isinstance(next_billing, (int, float)):
                                    next_date = datetime.fromtimestamp(int(next_billing))
                                else:
                                    next_date = datetime.fromisoformat(str(next_billing).replace('Z', '+00:00'))
                                content_parts.append(f'<p style="margin:8px 0 0 0;color:#c7c7c7">Next billing date: <strong>{next_date.strftime("%B %d, %Y")}</strong></p>')
                            except Exception:
                                pass
                        
                        extra = ''.join(content_parts)
                        
                        # Send the email using base.html template
                        _send_billing_email(
                            email,
                            subject,
                            intro,
                            content_html=extra,
                            cta_label='View Dashboard' if is_new_subscription else 'Manage Billing',
                            cta_url=os.getenv('FRONTEND_URL', 'https://cleanenroll.com').rstrip('/') + '/dashboard' if is_new_subscription else portal,
                            title=title
                        )
                        logger.info('[payments] sent %s email to %s', 'upgrade thank you' if is_new_subscription else 'renewal confirmation', email)
                except Exception:
                    logger.exception('[payments] failed to send upgrade/renewal email for uid=%s', uid)
        elif event_type in ('payment.succeeded', 'payment.failed'):
            # Record one-time payment events into owner ledger for Earnings dashboard
            try:
                await _record_owner_transaction(data, event_type)
            except Exception:
                logger.exception('[dodo-webhook] failed to record owner transaction')
        else:
            logger.info('[dodo-webhook] unhandled event type=%s', event_type)
        return { 'received': True }
    except Exception:
        logger.exception('[dodo-webhook] error handling event')
        raise HTTPException(status_code=400, detail='Webhook handling failed')

@router.post('/dodo/cancel')
async def dodo_cancel_or_resume(request: Request, payload: Dict):
    """Request cancel/resume/cancel-now for a Dodo subscription.

    Actions:
    - cancel_at_period_end: Set provider flag to cancel at next billing; update local after provider success
    - resume: Unset cancel-at-period-end at provider; update local after provider success
    - cancel_now: Immediately cancel at provider; then emit local cancellation side-effects

    Notes:
    - We resolve the subscription_id from Firestore (planDetails.subscription_id).
    - We no longer proceed with local state updates if the provider call fails to avoid dashboard mismatch.
    """
    action = (payload or {}).get('action')
    if action not in ('cancel_at_period_end', 'resume', 'cancel_now'):
        raise HTTPException(status_code=400, detail='Invalid action')

    # Identify user
    uid = _verify_id_token_from_header(request)
    if not uid:
        raise HTTPException(status_code=401, detail='Unauthorized')

    # Resolve subscription_id from Neon database
    subscription_id = None
    try:
        from db.database import async_session_maker
        from sqlalchemy import text as _text
        async with async_session_maker() as session:
            res = await session.execute(
                _text("SELECT subscription_id, plan_details FROM users WHERE uid = :uid LIMIT 1"),
                {"uid": uid}
            )
            row = res.mappings().first()
            if row:
                # Direct subscription_id column (preferred)
                subscription_id = row.get('subscription_id')
                # Fallback to plan_details JSON if subscription_id not set
                if not subscription_id and row.get('plan_details'):
                    plan_details = row.get('plan_details') or {}
                    subscription_id = plan_details.get('subscription_id') or plan_details.get('id')
    except Exception:
        logger.exception('[dodo-cancel] failed to resolve subscription_id for uid=%s', uid)

    if not subscription_id:
        # Without a subscription id, we cannot update provider
        logger.warning('[dodo-cancel] no subscription_id on record for uid=%s; refusing local-only change', uid)
        raise HTTPException(status_code=409, detail='No active subscription found for this account')

    # Prepare provider update payload based on action
    update_payload: Dict = {}
    if action == 'cancel_at_period_end':
        update_payload = {'cancel_at_next_billing_date': True}
    elif action == 'resume':
        update_payload = {'cancel_at_next_billing_date': False}
    elif action == 'cancel_now':
        update_payload = {'status': 'cancelled'}

    # Try provider API call paths
    api_key = os.getenv('DODO_API_KEY') or os.getenv('DODO_PAYMENTS_API_KEY')
    if not api_key:
        raise HTTPException(status_code=500, detail='Payments provider not configured')

    # Option A: Direct subscriptions update URL template (preferred)
    tmpl = os.getenv('DODO_SUBSCRIPTION_UPDATE_URL_TEMPLATE')  # e.g. https://api.dodopayments.com/subscriptions/{subscription_id}
    method = os.getenv('DODO_SUBSCRIPTION_UPDATE_METHOD', 'PATCH').upper()

    # Option B: Backward-compat "manage" URL (internal proxy) that accepts subscription-aware payloads
    manage_url = os.getenv('DODO_MANAGE_SUBSCRIPTION_URL')

    # Assemble headers
    auth_header = os.getenv('DODO_AUTH_HEADER', 'Authorization')
    auth_scheme = os.getenv('DODO_AUTH_SCHEME', 'Bearer')
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    if auth_header.lower() == 'authorization':
        headers['Authorization'] = f"{auth_scheme} {api_key}".strip()
    else:
        headers[auth_header] = api_key

    def _http_call(url: str, method_: str, body: Dict) -> None:
        req = urllib.request.Request(
            url=url,
            data=json.dumps(body).encode('utf-8'),
            headers=headers,
            method=method_,
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            # ensure 2xx
            if resp.status < 200 or resp.status >= 300:
                raw = resp.read().decode('utf-8', errors='replace')
                logger.warning('[dodo-cancel] provider non-2xx status=%s body=%s', resp.status, raw[:500])
                raise HTTPException(status_code=502, detail='Provider update failed')

    # Execute provider update
    provider_success = False
    try:
        if tmpl:
            try:
                url = tmpl.format(subscription_id=subscription_id)
            except Exception:
                # Support {id} as alternative placeholder
                url = tmpl.replace('{id}', subscription_id)
            provider_body = {**update_payload}
            _http_call(url, method, provider_body)
            logger.info('[dodo-cancel] provider updated via template url action=%s uid=%s sub=%s', action, uid, subscription_id)
            provider_success = True
        elif manage_url:
            # Send a richer body so legacy proxy endpoints can perform the correct Dodo call
            proxy_body = {
                'action': action,
                'subscription_id': subscription_id,
                'user_uid': uid,
                'dodo_update_payload': update_payload,
            }
            _http_call(manage_url, 'POST', proxy_body)
            logger.info('[dodo-cancel] provider updated via manage url action=%s uid=%s sub=%s', action, uid, subscription_id)
            provider_success = True
        else:
            logger.error('[dodo-cancel] no provider endpoint configured (set DODO_SUBSCRIPTION_UPDATE_URL_TEMPLATE or DODO_MANAGE_SUBSCRIPTION_URL)')
            # In development, allow local-only cancellation
            if os.getenv('ENV', 'production').lower() in ('development', 'dev', 'local'):
                logger.warning('[dodo-cancel] DEV MODE: proceeding with local-only cancellation')
                provider_success = True
            else:
                raise HTTPException(status_code=500, detail='Payments provider not configured')
    except urllib.error.HTTPError as he:  # type: ignore[attr-defined]
        try:
            err_body = he.read().decode('utf-8', errors='replace')  # type: ignore[call-arg]
        except Exception:
            err_body = ''
        status_code = getattr(he, 'code', 'unknown')
        logger.warning('[dodo-cancel] provider HTTPError status=%s body=%s', status_code, err_body[:500])
        # In development, allow local-only cancellation on provider failure
        if os.getenv('ENV', 'production').lower() in ('development', 'dev', 'local'):
            logger.warning('[dodo-cancel] DEV MODE: provider failed, proceeding with local-only cancellation')
            provider_success = True
        else:
            error_detail = f'Payment provider returned error (status {status_code}). Please contact support or try again later.'
            raise HTTPException(status_code=502, detail=error_detail)
    except urllib.error.URLError as ue:  # type: ignore[attr-defined]
        reason = str(getattr(ue, 'reason', ue))
        logger.warning('[dodo-cancel] provider URLError reason=%s', reason)
        # In development, allow local-only cancellation on provider failure
        if os.getenv('ENV', 'production').lower() in ('development', 'dev', 'local'):
            logger.warning('[dodo-cancel] DEV MODE: provider unreachable, proceeding with local-only cancellation')
            provider_success = True
        else:
            raise HTTPException(status_code=502, detail='Payment provider is currently unreachable. Please try again later.')
    except HTTPException:
        raise
    except Exception as e:
        logger.exception('[dodo-cancel] provider call failed')
        # In development, allow local-only cancellation on provider failure
        if os.getenv('ENV', 'production').lower() in ('development', 'dev', 'local'):
            logger.warning('[dodo-cancel] DEV MODE: provider error, proceeding with local-only cancellation')
            provider_success = True
        else:
            raise HTTPException(status_code=502, detail=f'Failed to contact payment provider: {str(e)[:100]}')
    
    if not provider_success:
        raise HTTPException(status_code=502, detail='Provider update failed')

    # Provider succeeded -> update local state
    if action == 'cancel_at_period_end':
        _update_user_billing(uid, {'cancelAtPeriodEnd': True})
        return {'success': True, 'cancelAtPeriodEnd': True}
    if action == 'resume':
        _update_user_billing(uid, {'cancelAtPeriodEnd': False})
        return {'success': True, 'cancelAtPeriodEnd': False}

    # cancel_now flow: emit local cancellation side-effects after provider success
    try:
        await _process_dodo_event({
            'type': 'subscription.cancelled',
            'data': {'metadata': {'user_uid': uid}}
        })
        try:
            _forward_dodo_event('subscription.cancelled', uid)  # optional best-effort forwarder if present
        except Exception:
            pass
        return {'success': True, 'cancelled': True}
    except Exception:
        logger.exception('[dodo-cancel] failed to finalize local cancellation after provider success')
        raise HTTPException(status_code=500, detail='Failed to finalize cancellation')


@router.post('/dodo/webhook')
async def dodo_webhook(payload: Dict, request: Request):
    """Handle Dodo Payments webhook events with signature verification (Standard Webhooks)."""
    # Read raw body for signature verification
    raw_body = await request.body()
    raw_text = raw_body.decode('utf-8', errors='replace') if isinstance(raw_body, (bytes, bytearray)) else str(raw_body or '')

    # Verify Standard Webhooks signature
    headers = request.headers
    webhook_id = headers.get('webhook-id')
    webhook_sig = (
        headers.get('webhook-signature')
        or headers.get('dodo-signature')
        or headers.get('x-dodo-signature')
        or headers.get('signature')
    )
    webhook_ts = headers.get('webhook-timestamp') or headers.get('webhook-time') or headers.get('timestamp')
    secret = os.getenv('DODO_WEBHOOK_SECRET') or os.getenv('DODO_PAYMENTS_WEBHOOK_KEY')

    if not (webhook_id and webhook_sig and webhook_ts and secret):
        raise HTTPException(status_code=401, detail='Invalid webhook signature')

    try:
        ts = int(str(webhook_ts))
        now = int(time.time())
        tolerance = int(os.getenv('DODO_WEBHOOK_TOLERANCE', '300'))
        if abs(now - ts) > tolerance:
            raise HTTPException(status_code=401, detail='Webhook timestamp outside tolerance')
    except ValueError:
        raise HTTPException(status_code=401, detail='Invalid webhook timestamp')

    if not _STDWEBHOOKS_AVAILABLE:
        logger.error('[dodo-webhook] standardwebhooks library is not available on server')
        raise HTTPException(status_code=500, detail='Webhook verification library unavailable')

    try:
        wh = Webhook(secret)
        std_headers = {
            'webhook-id': webhook_id,
            'webhook-signature': webhook_sig,
            'webhook-timestamp': str(webhook_ts),
        }
        wh.verify(raw_text, std_headers)
        logger.info('[dodo-webhook] signature verified via standardwebhooks')
    except Exception:
        logger.warning('[dodo-webhook] signature verification failed')
        raise HTTPException(status_code=401, detail='Invalid webhook signature')

    # Parse payload from raw_text to ensure signature matches content
    try:
        parsed = json.loads(raw_text) if raw_text else {}
        if isinstance(parsed, dict):
            payload = parsed
    except Exception:
        payload = payload or {}

    # Process event
    return await _process_dodo_event(payload)
