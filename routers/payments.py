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

# Firestore Admin to update user's plan/billing
try:
    from utils.firebase_admin_adapter import admin_firestore as _fs
    _FS_AVAILABLE = True
except Exception:
    _FS_AVAILABLE = False

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


def _update_user_billing(uid: str, updates: Dict):
    if not _FS_AVAILABLE or not uid:
        return
    try:
        ref = _fs.client().collection('users').document(uid)
        doc = ref.get()
        data = doc.to_dict() or {}
        billing = data.get('billing') or {}
        billing.update(updates)
        ref.update({'billing': billing})
    except Exception:
        logger.exception('[payments] failed to update user billing uid=%s', uid)


def _set_user_plan(uid: str, plan: str):
    if not _FS_AVAILABLE or not uid:
        return
    try:
        ref = _fs.client().collection('users').document(uid)
        ref.update({'plan': plan})
    except Exception:
        logger.exception('[payments] failed to set user plan uid=%s', uid)


def _get_user_email(uid: str) -> Optional[str]:
    """Fetch user's email from Firestore by uid, if available."""
    if not _FS_AVAILABLE or not uid:
        return None
    try:
        ref = _fs.client().collection('users').document(uid)
        snap = ref.get()
        data = snap.to_dict() or {}
        email = data.get('email')
        if isinstance(email, str) and '@' in email:
            return email.strip()
    except Exception:
        logger.warning('[payments] failed to get user email for uid=%s', uid)
    return None


def _send_billing_email(to_email: str, subject: str, intro: str, content_html: Optional[str] = None, cta_label: Optional[str] = None, cta_url: Optional[str] = None):
    """Render and send a branded billing email from billing@cleanenroll.com."""
    try:
        html = render_email('base.html', {
            'subject': subject,
            'preheader': intro,
            'title': subject,
            'intro': intro,
            'content_html': content_html or '',
            'cta_label': cta_label,
            'cta_url': cta_url,
        })
        send_email_html(to_email, subject, html, from_addr='billing@cleanenroll.com')
    except Exception:
        logger.exception('[payments] failed to send billing email to %s', to_email)


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

    # Resolve subscription_id from Firestore
    subscription_id = None
    if _FS_AVAILABLE:
        try:
            ref = _fs.client().collection('users').document(uid)
            snap = ref.get()
            data = snap.to_dict() or {}
            # prefer core webhook's mapping
            plan_details = data.get('planDetails') or {}
            subscription_id = plan_details.get('subscription_id') or plan_details.get('id')
            if not subscription_id:
                # legacy storage fallback
                billing = data.get('billing') or {}
                subscription_id = billing.get('subscriptionId') or billing.get('subscription_id')
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
        else:
            logger.error('[dodo-cancel] no provider endpoint configured (set DODO_SUBSCRIPTION_UPDATE_URL_TEMPLATE or DODO_MANAGE_SUBSCRIPTION_URL)')
            raise HTTPException(status_code=500, detail='Payments provider not configured')
    except urllib.error.HTTPError as he:  # type: ignore[attr-defined]
        try:
            err_body = he.read().decode('utf-8', errors='replace')  # type: ignore[call-arg]
        except Exception:
            err_body = ''
        logger.warning('[dodo-cancel] provider HTTPError status=%s body=%s', getattr(he, 'code', 'n/a'), err_body[:500])
        raise HTTPException(status_code=502, detail='Provider update failed')
    except urllib.error.URLError as ue:  # type: ignore[attr-defined]
        logger.warning('[dodo-cancel] provider URLError reason=%s', getattr(ue, 'reason', ue))
        raise HTTPException(status_code=502, detail='Provider unreachable')
    except HTTPException:
        raise
    except Exception:
        logger.exception('[dodo-cancel] provider call failed')
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
        await dodo_webhook({
            'type': 'subscription.cancelled',
            'data': {'metadata': {'user_uid': uid}}
        }, request)
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
    """Handle Dodo Payments webhook events.
    Expected event types include: subscription.cancelled, subscription.renewed, subscription.created
    We update Firestore billing and plan accordingly.
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
                _set_user_plan(uid, 'free')
                _update_user_billing(uid, {
                    'nextBillingAt': None,
                    'cancelAtPeriodEnd': False,
                    'status': 'cancelled',
                })
                # Notify user about cancellation (best-effort)
                try:
                    email = _get_user_email(uid)
                    if email:
                        portal = os.getenv('DODO_MANAGE_SUBSCRIPTION_URL') or (os.getenv('FRONTEND_URL', 'https://cleanenroll.com').rstrip('/') + '/billing/portal')
                        subject = 'Your CleanEnroll subscription was canceled'
                        intro = 'Your subscription has been canceled. You will no longer be charged.'
                        _send_billing_email(email, subject, intro, cta_label='Manage Billing', cta_url=portal)
                except Exception:
                    logger.exception('[payments] failed to send cancellation email for uid=%s', uid)
        elif event_type in ('subscription.renewed', 'subscription.created', 'invoice.paid'):
            if uid:
                _set_user_plan(uid, 'pro')
                # Best-effort payment identifier extraction (depends on provider payload)
                payment_id = (
                    data.get('payment_id')
                    or data.get('invoice_id')
                    or data.get('id')
                    or (data.get('payment') or {}).get('id')
                    or (data.get('invoice') or {}).get('id')
                )
                _update_user_billing(uid, {
                    'nextBillingAt': normalize_ts(next_billing),
                    'cancelAtPeriodEnd': False,
                    'currency': currency,
                    'price': price_amount if isinstance(price_amount, (int, float)) else None,
                    'status': 'active',
                    'paymentMethod': payment_method if isinstance(payment_method, dict) else None,
                    **({'lastPaymentId': payment_id} if payment_id else {}),
                })
                # Notify user about successful upgrade/renewal (best-effort)
                try:
                    email = _get_user_email(uid)
                    if email:
                        portal = os.getenv('DODO_MANAGE_SUBSCRIPTION_URL') or (os.getenv('FRONTEND_URL', 'https://cleanenroll.com').rstrip('/') + '/billing/portal')
                        subject = 'Your CleanEnroll subscription is active'
                        intro = 'Your plan has been upgraded/renewed successfully.'
                        extra = ''
                        if isinstance(price_amount, (int, float)) and currency:
                            try:
                                amt = float(price_amount) / (100.0 if price_amount and price_amount > 50 else 1.0)
                                extra = f"<p style='margin:0;color:#c7c7c7'>Amount: <strong>{amt:.2f} {currency}</strong></p>"
                            except Exception:
                                extra = ''
                        _send_billing_email(email, subject, intro, content_html=extra, cta_label='Manage Billing', cta_url=portal)
                except Exception:
                    logger.exception('[payments] failed to send upgrade/renewal email for uid=%s', uid)
        else:
            logger.info('[dodo-webhook] unhandled event type=%s', event_type)
        return { 'received': True }
    except Exception:
        logger.exception('[dodo-webhook] error handling event')
        raise HTTPException(status_code=400, detail='Webhook handling failed')
