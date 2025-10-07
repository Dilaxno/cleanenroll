import os
import json
import base64
import hmac
import hashlib
import logging
from typing import Dict, Any, List, Optional
import time
from urllib.parse import urlencode, quote_plus

import requests
from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import RedirectResponse

# Firebase Admin
import firebase_admin
from firebase_admin import credentials, firestore

logger = logging.getLogger("backend.mailchimp")

# Initialize Firebase app if not already
if not firebase_admin._apps:
    cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.path.join(os.getcwd(), "cleanenroll-fd36a-firebase-adminsdk-fbsvc-7d79b92b3f.json")
    if not os.path.exists(cred_path):
        raise RuntimeError("Firebase credentials JSON not found; set GOOGLE_APPLICATION_CREDENTIALS")
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()

router = APIRouter(prefix="/api/integrations/mailchimp", tags=["mailchimp"]) 


def _is_pro_plan(user_id: str) -> bool:
    try:
        snap = db.collection("users").document(user_id).get()
        data = snap.to_dict() or {}
        plan = str(data.get("plan") or "").lower()
        return plan in ("pro", "business", "enterprise")
    except Exception:
        return False 

# OAuth config (set via env)
MAILCHIMP_CLIENT_ID = os.getenv("MAILCHIMP_CLIENT_ID", "")
MAILCHIMP_CLIENT_SECRET = os.getenv("MAILCHIMP_CLIENT_SECRET", "")
MAILCHIMP_REDIRECT_URI = os.getenv("MAILCHIMP_REDIRECT_URI", "https://api.cleanenroll.com/api/integrations/mailchimp/callback")
ENCRYPTION_SECRET = (os.getenv("ENCRYPTION_SECRET") or "change-this-secret").encode("utf-8")
# Optional: where to send users after successful connect (e.g., your dashboard)
FRONTEND_REDIRECT_URL = os.getenv("FRONTEND_REDIRECT_URL", "https://cleanenroll.com/dashboard?integrations=mailchimp&status=connected")

if not MAILCHIMP_CLIENT_ID or not MAILCHIMP_CLIENT_SECRET:
    logger.warning("Mailchimp OAuth not configured: missing client id/secret")

# Simple symmetric encryption using HMAC+XOR for demonstration
# In production, use a proper KMS or cryptography.Fernet with key rotation

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def _encrypt_token(token: str) -> str:
    raw = token.encode("utf-8")
    mac = hmac.new(ENCRYPTION_SECRET, raw, hashlib.sha256).digest()
    xored = _xor_bytes(raw, mac)
    return base64.urlsafe_b64encode(mac + xored).decode("utf-8")


def _decrypt_token(ciphertext: str) -> str:
    blob = base64.urlsafe_b64decode(ciphertext.encode("utf-8"))
    mac = blob[:32]
    xored = blob[32:]
    raw = _xor_bytes(xored, mac)
    # Verify MAC
    if not hmac.compare_digest(mac, hmac.new(ENCRYPTION_SECRET, raw, hashlib.sha256).digest()):
        raise ValueError("Token MAC verification failed")
    return raw.decode("utf-8")


# Token helpers for Mailchimp (best-effort refresh support)

def _get_mailchimp_tokens(user_id: str):
    doc = _get_user_doc(user_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")
    data = doc.to_dict() or {}
    integ = ((data.get("integrations") or {}).get("mailchimp") or {})
    tok_enc = integ.get("token")
    rtok_enc = integ.get("refreshToken")
    expiry = int(integ.get("expiry") or 0)
    dc = integ.get("dc")
    api_base = integ.get("apiBase") or (f"https://{dc}.api.mailchimp.com/3.0" if dc else None)
    if not tok_enc or not dc:
        raise HTTPException(status_code=400, detail="Mailchimp not connected for this user")
    access = _decrypt_token(tok_enc)
    refresh = _decrypt_token(rtok_enc) if rtok_enc else None
    return access, refresh, expiry, dc, api_base


def _save_mailchimp_tokens(user_id: str, access_token: str, refresh_token: Optional[str], expires_in: Optional[int]):
    payload: Dict[str, Any] = {"token": _encrypt_token(access_token)}
    if refresh_token:
        payload["refreshToken"] = _encrypt_token(refresh_token)
    if expires_in:
        payload["expiry"] = int(time.time()) + int(expires_in)
    _get_user_doc(user_id).set({"integrations": {"mailchimp": payload}}, merge=True)


def _get_valid_mailchimp_token(user_id: str) -> str:
    access, refresh, expiry, _dc, _api = _get_mailchimp_tokens(user_id)
    now = int(time.time())
    if expiry and now < (expiry - 60):
        return access
    if not refresh:
        # Mailchimp typically does not issue refresh tokens; keep using current token
        return access
    # Attempt refresh (if provider supports it). Ignore errors and fallback to existing access.
    try:
        token_url = "https://login.mailchimp.com/oauth2/token"
        data = {
            "grant_type": "refresh_token",
            "client_id": MAILCHIMP_CLIENT_ID,
            "client_secret": MAILCHIMP_CLIENT_SECRET,
            "refresh_token": refresh,
        }
        resp = requests.post(token_url, data=data, timeout=15)
        if resp.status_code == 200:
            j = resp.json()
            new_access = j.get("access_token") or access
            expires_in = j.get("expires_in")
            # Mailchimp may not return refresh_token on refresh
            _save_mailchimp_tokens(user_id, new_access, refresh, expires_in)
            return new_access
        else:
            logger.warning("Mailchimp token refresh failed: %s", resp.text)
            return access
    except Exception:
        logger.exception("Mailchimp token refresh error")
        return access


def _get_user_doc(user_id: str):
    return db.collection("users").document(user_id)


@router.get("/authorize")
def authorize(userId: str = Query(...), redirect: Optional[str] = Query(None)):
    """
    Step 1: Redirect URL for Mailchimp OAuth. Frontend should redirect the user-agent here.
    We return the URL so the client can navigate to it.
    """
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Mailchimp integration is available on Pro plans.")
    if not MAILCHIMP_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Mailchimp not configured")

    scope = "audience:read audience:write"  # lists read/write
    state_data = {"userId": userId}
    if redirect:
        state_data["redirect"] = redirect
    state = json.dumps(state_data)
    params = {
        "response_type": "code",
        "client_id": MAILCHIMP_CLIENT_ID,
        "redirect_uri": MAILCHIMP_REDIRECT_URI,
        "scope": scope,
        "state": state,
    }
    url = f"https://login.mailchimp.com/oauth2/authorize?{urlencode(params, quote_via=quote_plus)}"
    return {"authorize_url": url}


@router.get("/callback")
def callback(code: str = Query(None), state: str = Query("{}")):
    """
    Step 2: OAuth callback. Exchanges code for access token and stores it (encrypted) under the user document.
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    try:
        parsed_state = json.loads(state or "{}")
    except Exception:
        parsed_state = {}
    user_id = parsed_state.get("userId")
    if not user_id:
        raise HTTPException(status_code=400, detail="Missing userId in state")
    if not _is_pro_plan(str(user_id)):
        raise HTTPException(status_code=403, detail="Mailchimp integration is available on Pro plans.")

    token_url = "https://login.mailchimp.com/oauth2/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": MAILCHIMP_CLIENT_ID,
        "client_secret": MAILCHIMP_CLIENT_SECRET,
        "redirect_uri": MAILCHIMP_REDIRECT_URI,
        "code": code,
    }
    resp = requests.post(token_url, data=data, timeout=15)
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"OAuth exchange failed: {resp.text}")
    token_payload = resp.json()
    access_token = token_payload.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="OAuth exchange missing access_token")

    # Determine API base (data center) via metadata endpoint
    meta_resp = requests.get(
        "https://login.mailchimp.com/oauth2/metadata",
        headers={"Authorization": f"OAuth {access_token}"},
        timeout=15,
    )
    if meta_resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Failed to read metadata: {meta_resp.text}")
    meta = meta_resp.json()
    dc = meta.get("dc")
    api_base = f"https://{dc}.api.mailchimp.com/3.0"
    # Optional refresh support (Mailchimp may not issue refresh_token; handle if present)
    refresh_token = token_payload.get("refresh_token")
    expires_in = token_payload.get("expires_in")
    enc_refresh = _encrypt_token(refresh_token) if refresh_token else None

    # Store encrypted token + dc under users/{userId}/integrations/mailchimp
    enc = _encrypt_token(access_token)
    doc = _get_user_doc(user_id)
    doc.set({
        "integrations": {
            "mailchimp": {
                "token": enc,
                "dc": dc,
                "apiBase": api_base,
                "refreshToken": enc_refresh if enc_refresh else None,
                "expiry": (int(time.time()) + int(expires_in)) if expires_in else None,
            }
        }
    }, merge=True)

    # After successful connection, redirect user back to the frontend if configured
    redirect_target = parsed_state.get("redirect") or FRONTEND_REDIRECT_URL
    if redirect_target:
        return RedirectResponse(url=redirect_target, status_code=302)

    return {"connected": True}


def _get_mailchimp_auth(user_id: str) -> Dict[str, str]:
    # Retrieve API base and data center; validate token or refresh when possible
    doc = _get_user_doc(user_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")
    data = doc.to_dict() or {}
    integ = ((data.get("integrations") or {}).get("mailchimp") or {})
    dc = integ.get("dc")
    api_base = integ.get("apiBase")
    if not dc:
        raise HTTPException(status_code=400, detail="Mailchimp not connected for this user")
    token = _get_valid_mailchimp_token(user_id)
    return {"token": token, "dc": dc, "api_base": api_base or f"https://{dc}.api.mailchimp.com/3.0"}


@router.post("/disconnect")
def disconnect(userId: str = Query(...)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Mailchimp integration is available on Pro plans.")
    doc_ref = _get_user_doc(userId)
    snap = doc_ref.get()
    data = snap.to_dict() or {}
    integ = (data.get("integrations") or {})
    if "mailchimp" in integ:
        integ.pop("mailchimp", None)
    doc_ref.set({"integrations": integ}, merge=True)
    return {"disconnected": True}

@router.get("/audiences")
def list_audiences(userId: str = Query(...)):
    """List audiences (lists) for the connected Mailchimp account."""
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Mailchimp integration is available on Pro plans.")
    auth = _get_mailchimp_auth(userId)
    url = f"{auth['api_base']}/lists"
    resp = requests.get(url, headers={"Authorization": f"Bearer {auth['token']}"}, timeout=20)
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Failed to list audiences: {resp.text}")
    data = resp.json()
    # Return minimal fields
    out = [{
        "id": x.get("id"),
        "name": x.get("name"),
        "member_count": (x.get("stats") or {}).get("member_count"),
    } for x in (data.get("lists") or [])]
    return {"lists": out}


@router.post("/export")
def export_members(
    userId: str = Query(...),
    formId: str = Query(...),
    listId: str = Query(...),
    status: str = Query("subscribed"),  # or "pending" for double opt-in
):
    """
    Export subscribers collected for a form to a Mailchimp audience.
    Reads stored responses for that form and submits members to /lists/{list_id}/members
    """
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Mailchimp integration is available on Pro plans.")
    if status not in ("subscribed", "pending"):
        raise HTTPException(status_code=400, detail="Invalid status")

    # Read responses from filesystem store used by builder router
    responses_dir = os.path.join(os.getcwd(), "data", "responses", formId)
    if not os.path.exists(responses_dir):
        return {"exported": 0, "skipped": 0}

    # Gather emails and merge fields heuristically from stored answers
    members: List[Dict[str, Any]] = []
    for name in os.listdir(responses_dir):
        if not name.endswith('.json'):
            continue
        try:
            with open(os.path.join(responses_dir, name), 'r', encoding='utf-8') as f:
                rec = json.load(f)
            answers = rec.get('answers') or {}
            email = None
            merge_fields: Dict[str, Any] = {}
            # Try typical keys
            for k, v in answers.items():
                lk = str(k).lower()
                try:
                    sv = v if isinstance(v, str) else (v[0] if isinstance(v, list) and v else None)
                except Exception:
                    sv = None
                if not sv:
                    continue
                if ("email" in lk) and (not email):
                    email = str(sv).strip()
                elif any(x in lk for x in ["name", "full-name", "first", "last", "phone", "company"]):
                    merge_fields[lk[:10].upper()] = str(sv)[:255]
            if email:
                members.append({"email_address": email, "status": status, "merge_fields": merge_fields})
        except Exception:
            continue

    if not members:
        return {"exported": 0, "skipped": 0}

    auth = _get_mailchimp_auth(userId)
    url = f"{auth['api_base']}/lists/{listId}/members"

    exported = 0
    skipped = 0
    for m in members:
        resp = requests.post(url, headers={"Authorization": f"Bearer {auth['token']}", "Content-Type": "application/json"}, data=json.dumps(m), timeout=20)
        if resp.status_code in (200, 201):
            exported += 1
        else:
            # If member exists (400 with title "Member Exists"), count as skipped
            try:
                err = resp.json()
                if str(err.get('title')).lower().find('exists') != -1:
                    skipped += 1
                    continue
            except Exception:
                pass
            logger.warning("Mailchimp add member failed: %s", resp.text)
            skipped += 1

    return {"exported": exported, "skipped": skipped, "total": len(members)}


@router.post("/create-and-export")
def create_and_export(
    userId: str = Query(...),
    formId: str = Query(...),
    audienceName: str = Query(...),
    status: str = Query("subscribed"),  # or "pending" for double opt-in
):
    """
    Create a new Mailchimp audience and export subscribers collected for a form to it.
    The audience name is provided by the user. Members will be added using email and
    best-effort name parsing into FNAME/LNAME.
    """
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Mailchimp integration is available on Pro plans.")
    if status not in ("subscribed", "pending"):
        raise HTTPException(status_code=400, detail="Invalid status")
    audienceName = (audienceName or "").strip()
    if not audienceName:
        raise HTTPException(status_code=400, detail="audienceName is required")

    # Read responses from filesystem store used by builder router
    responses_dir = os.path.join(os.getcwd(), "data", "responses", formId)
    if not os.path.exists(responses_dir):
        # Nothing to export; still create the audience
        members: List[Dict[str, Any]] = []
    else:
        # Gather emails and name fields heuristically from stored answers
        members = []
        for name in os.listdir(responses_dir):
            if not name.endswith('.json'):
                continue
            try:
                with open(os.path.join(responses_dir, name), 'r', encoding='utf-8') as f:
                    rec = json.load(f)
                answers = rec.get('answers') or {}
                email = None
                first_name: Optional[str] = None
                last_name: Optional[str] = None
                full_name: Optional[str] = None
                # Try typical keys
                for k, v in answers.items():
                    lk = str(k).lower()
                    try:
                        sv = v if isinstance(v, str) else (v[0] if isinstance(v, list) and v else None)
                    except Exception:
                        sv = None
                    if not sv:
                        continue
                    ssv = str(sv).strip()
                    if ("email" in lk) and (not email):
                        email = ssv
                    elif ("first" in lk and "name" in lk) and not first_name:
                        first_name = ssv
                    elif ("last" in lk and "name" in lk) and not last_name:
                        last_name = ssv
                    elif any(x in lk for x in ["full-name", "fullname"]) or (lk == "name"):
                        full_name = ssv
                # Derive first/last from full name when split fields missing
                if (not first_name or not last_name) and full_name:
                    parts = [p for p in full_name.split() if p.strip()]
                    if len(parts) == 1:
                        first_name = first_name or parts[0]
                    elif len(parts) >= 2:
                        first_name = first_name or parts[0]
                        last_name = last_name or " ".join(parts[1:])
                if email:
                    mf: Dict[str, Any] = {}
                    if first_name:
                        mf["FNAME"] = first_name[:255]
                    if last_name:
                        mf["LNAME"] = last_name[:255]
                    members.append({"email_address": email, "status": status, "merge_fields": mf})
            except Exception:
                continue

    auth = _get_mailchimp_auth(userId)

    # Create the audience (list)
    # Derive optional defaults from user profile if present
    try:
        udoc = _get_user_doc(userId).get()
        udata = (udoc.to_dict() or {}) if udoc and udoc.exists else {}
    except Exception:
        udata = {}
    from_email = (udata.get("email") or (udata.get("profile") or {}).get("email") or "no-reply@cleanenroll.com")
    from_name = (udata.get("name") or (udata.get("profile") or {}).get("name") or "CleanEnroll User")
    company = (udata.get("company") or (udata.get("profile") or {}).get("company") or audienceName)
    address_obj = (udata.get("address") or (udata.get("profile") or {}).get("address") or {})
    address1 = (address_obj.get("address1") if isinstance(address_obj, dict) else None) or "123 Main St"
    city = (address_obj.get("city") if isinstance(address_obj, dict) else None) or "City"
    state = (address_obj.get("state") if isinstance(address_obj, dict) else None) or ""
    zip_code = (address_obj.get("zip") if isinstance(address_obj, dict) else None) or "00000"
    country = (address_obj.get("country") if isinstance(address_obj, dict) else None) or "US"

    list_payload = {
        "name": audienceName,
        "contact": {
            "company": str(company)[:200],
            "address1": str(address1)[:200],
            "city": str(city)[:200],
            "state": str(state)[:50],
            "zip": str(zip_code)[:50],
            "country": str(country)[:2]
        },
        "permission_reminder": "You're receiving this email because you opted in via our website.",
        "campaign_defaults": {
            "from_name": str(from_name)[:100],
            "from_email": str(from_email)[:254],
            "subject": "",
            "language": "en"
        },
        "email_type_option": False
    }

    create_url = f"{auth['api_base']}/lists"
    create_resp = requests.post(
        create_url,
        headers={"Authorization": f"Bearer {auth['token']}", "Content-Type": "application/json"},
        data=json.dumps(list_payload),
        timeout=30,
    )
    if create_resp.status_code not in (200, 201):
        # Graceful fallback: user may not be allowed to create audiences on their Mailchimp plan.
        # In this case, return existing audiences and guidance instead of failing outright.
        try:
            err_json = create_resp.json()
        except Exception:
            err_json = None
        title = (err_json or {}).get("title")
        detail = (err_json or {}).get("detail") or create_resp.text
        if create_resp.status_code == 403 or (title and "user action not permitted" in str(title).lower()):
            # Load available audiences so the client can pick one
            lists_url = f"{auth['api_base']}/lists"
            lists_resp = requests.get(lists_url, headers={"Authorization": f"Bearer {auth['token']}"}, timeout=20)
            available = []
            if lists_resp.status_code == 200:
                lists_data = lists_resp.json()
                available = [{
                    "id": x.get("id"),
                    "name": x.get("name"),
                    "member_count": (x.get("stats") or {}).get("member_count"),
                } for x in (lists_data.get("lists") or [])]
            tip = (
                "You need to create an audience in Mailchimp before sending contacts to it. Steps: "
                "1) Log in to Mailchimp. 2) Go to Audience > Audience dashboard. "
                "3) If you don't have an audience, click Create Audience and fill in company address and permission reminder. "
                "4) After it is created, come back here, select that audience, and run the export again."
            )
            return {
                "createdListId": None,
                "createdListName": None,
                "exported": 0,
                "skipped": 0,
                "total": len(members),
                "error": {"status": create_resp.status_code, "title": title or "User action not permitted", "detail": detail},
                "availableAudiences": available,
                "tip": tip,
            }
        # Other errors: propagate
        raise HTTPException(status_code=400, detail=f"Failed to create audience: {detail}")
    created = create_resp.json()
    list_id = created.get("id")
    if not list_id:
        raise HTTPException(status_code=400, detail="Audience created but id missing in response")

    # Add members
    exported = 0
    skipped = 0
    if members:
        add_url = f"{auth['api_base']}/lists/{list_id}/members"
        for m in members:
            # Clean empty merge_fields to avoid 400s
            mf = m.get("merge_fields") or {}
            if not mf:
                m.pop("merge_fields", None)
            resp = requests.post(
                add_url,
                headers={"Authorization": f"Bearer {auth['token']}", "Content-Type": "application/json"},
                data=json.dumps(m),
                timeout=20,
            )
            if resp.status_code in (200, 201):
                exported += 1
            else:
                try:
                    err = resp.json()
                    if str(err.get('title')).lower().find('exists') != -1:
                        skipped += 1
                        continue
                except Exception:
                    pass
                logger.warning("Mailchimp add member failed: %s", resp.text)
                skipped += 1

    return {
        "createdListId": list_id,
        "createdListName": audienceName,
        "exported": exported,
        "skipped": skipped,
        "total": len(members)
    }
