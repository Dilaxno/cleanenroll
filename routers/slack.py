import os
import json
import base64
import hmac
import hashlib
import time
import logging
from typing import Dict, Any, Optional, List, Tuple

import requests
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import RedirectResponse

# Firebase Admin
import firebase_admin
from firebase_admin import credentials, firestore

logger = logging.getLogger("backend.slack")

# Initialize Firebase app if not already
if not firebase_admin._apps:
    cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.path.join(os.getcwd(), "cleanenroll-fd36a-firebase-adminsdk-fbsvc-7d79b92b3f.json")
    if not os.path.exists(cred_path):
        raise RuntimeError("Firebase credentials JSON not found; set GOOGLE_APPLICATION_CREDENTIALS")
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()

router = APIRouter(prefix="/api/integrations/slack", tags=["slack"]) 


# Plan gate

def _is_pro_plan(user_id: str) -> bool:
    try:
        snap = db.collection("users").document(user_id).get()
        data = snap.to_dict() or {}
        plan = str(data.get("plan") or "").lower()
        return plan in ("pro", "business", "enterprise")
    except Exception:
        return False


# Config
SLACK_CLIENT_ID = os.getenv("SLACK_CLIENT_ID", "")
SLACK_CLIENT_SECRET = os.getenv("SLACK_CLIENT_SECRET", "")
SLACK_REDIRECT_URI = os.getenv("SLACK_REDIRECT_URI", "https://api.cleanenroll.com/api/integrations/slack/callback")
FRONTEND_REDIRECT_URL = os.getenv("FRONTEND_REDIRECT_URL", "https://cleanenroll.com/dashboard?integrations=slack&status=connected")
ENCRYPTION_SECRET = (os.getenv("ENCRYPTION_SECRET") or "change-this-secret").encode("utf-8")


# Encryption helpers (HMAC+XOR, align with other integrations)

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def _encrypt(value: str) -> str:
    raw = value.encode("utf-8")
    mac = hmac.new(ENCRYPTION_SECRET, raw, hashlib.sha256).digest()
    xored = _xor_bytes(raw, mac)
    return base64.urlsafe_b64encode(mac + xored).decode("utf-8")


def _decrypt(ciphertext: str) -> str:
    blob = base64.urlsafe_b64decode(ciphertext.encode("utf-8"))
    mac = blob[:32]
    xored = blob[32:]
    raw = _xor_bytes(xored, mac)
    if not hmac.compare_digest(mac, hmac.new(ENCRYPTION_SECRET, raw, hashlib.sha256).digest()):
        raise ValueError("MAC verification failed")
    return raw.decode("utf-8")


def _get_user_doc(user_id: str):
    return db.collection("users").document(user_id)


# OAuth
@router.get("/authorize")
def authorize(userId: str = Query(...), redirect: Optional[str] = Query(None)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Slack integration is available on Pro plans.")
    if not SLACK_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Slack OAuth not configured")
    state = json.dumps({"userId": userId, **({"redirect": redirect} if redirect else {})})
    from urllib.parse import urlencode, quote_plus
    scopes = [
        "chat:write",
        "incoming-webhook",
        "channels:read",
    ]
    params = {
        "client_id": SLACK_CLIENT_ID,
        "scope": " ".join(scopes),
        "user_scope": "",
        "redirect_uri": SLACK_REDIRECT_URI,
        "state": state,
    }
    url = f"https://slack.com/oauth/v2/authorize?{urlencode(params, quote_via=quote_plus)}"
    return {"authorize_url": url}


@router.get("/callback")
def callback(code: str = Query(None), state: str = Query("{}")):
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    try:
        st = json.loads(state or "{}")
    except Exception:
        st = {}
    user_id = st.get("userId")
    if not user_id:
        raise HTTPException(status_code=400, detail="Missing userId in state")
    if not _is_pro_plan(str(user_id)):
        raise HTTPException(status_code=403, detail="Slack integration is available on Pro plans.")

    resp = requests.post(
        "https://slack.com/api/oauth.v2.access",
        data={
            "client_id": SLACK_CLIENT_ID,
            "client_secret": SLACK_CLIENT_SECRET,
            "code": code,
            "redirect_uri": SLACK_REDIRECT_URI,
        },
        timeout=20,
    )
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"OAuth exchange failed: {resp.text}")
    data = resp.json()
    if not data.get("ok"):
        raise HTTPException(status_code=400, detail=f"Slack OAuth error: {data}")

    access_token = data.get("access_token")  # xoxb-...
    bot_user_id = (data.get("bot_user_id") or "")
    incoming = data.get("incoming_webhook") or {}
    webhook_url = incoming.get("url")
    default_channel_name = incoming.get("channel")
    default_channel_id = incoming.get("channel_id")

    payload: Dict[str, Any] = {
        "token": _encrypt(access_token) if access_token else None,
        "botUserId": bot_user_id or None,
        "webhook": _encrypt(webhook_url) if webhook_url else None,
        "defaultChannelId": default_channel_id or None,
        "defaultChannel": default_channel_name or None,
        "connectedAt": int(time.time()),
    }
    _get_user_doc(user_id).set({"integrations": {"slack": payload}}, merge=True)

    target = st.get("redirect") or FRONTEND_REDIRECT_URL
    return RedirectResponse(url=target, status_code=302)


def _get_slack_creds(user_id: str) -> Tuple[Optional[str], Optional[str]]:
    doc = _get_user_doc(user_id).get()
    data = doc.to_dict() or {}
    integ = ((data.get("integrations") or {}).get("slack") or {})
    tok_enc = integ.get("token")
    wh_enc = integ.get("webhook")
    token = _decrypt(tok_enc) if tok_enc else None
    webhook = _decrypt(wh_enc) if wh_enc else None
    return token, webhook


@router.get("/status")
def status(userId: str = Query(...), formId: Optional[str] = Query(None)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Slack integration is available on Pro plans.")
    token, webhook = _get_slack_creds(userId)
    connected = bool(token or webhook)
    mapping = None
    if formId:
        snap = _get_user_doc(userId).get()
        data = snap.to_dict() or {}
        mp = ((data.get("integrations") or {}).get("slackMappings") or {})
        mapping = mp.get(formId)
    return {"connected": connected, "mapping": mapping}


@router.get("/channels")
def list_channels(userId: str = Query(...)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Slack integration is available on Pro plans.")
    token, _ = _get_slack_creds(userId)
    if not token:
        return {"channels": []}
    url = "https://slack.com/api/conversations.list?exclude_archived=true&types=public_channel,private_channel"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.get(url, headers=headers, timeout=20)
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Failed to fetch channels: {resp.text}")
    data = resp.json()
    if not data.get("ok"):
        raise HTTPException(status_code=400, detail=f"Slack API error: {data}")
    chans = []
    for ch in data.get("channels") or []:
        try:
            chans.append({"id": ch.get("id"), "name": ch.get("name"), "is_private": bool(ch.get("is_private"))})
        except Exception:
            continue
    return {"channels": chans}


@router.post("/configure")
def configure(userId: str = Query(...), formId: str = Query(...), payload: Dict[str, Any] = None):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Slack integration is available on Pro plans.")
    if not isinstance(payload, dict):
        payload = {}
    # Accept either channelId (for bot) or webhookUrl (manual)
    channel_id = (payload.get("channelId") or payload.get("channel") or "").strip() or None
    channel_name = (payload.get("channelName") or "").strip() or None
    webhook_url = (payload.get("webhookUrl") or "").strip() or None
    sync = bool(payload.get("sync"))

    doc_ref = _get_user_doc(userId)
    snap = doc_ref.get()
    data = snap.to_dict() or {}
    mappings = ((data.get("integrations") or {}).get("slackMappings") or {})
    entry: Dict[str, Any] = mappings.get(formId) or {}
    if channel_id:
        entry["channelId"] = channel_id
    if channel_name:
        entry["channelName"] = channel_name
    if webhook_url:
        entry["webhook"] = _encrypt(webhook_url)
    entry["synced"] = sync
    mappings[formId] = entry

    doc_ref.set({"integrations": {"slackMappings": mappings}}, merge=True)
    return {"mapping": {**entry, "webhook": bool(entry.get("webhook"))}}


def _send_via_webhook(webhook_url: str, record: Dict[str, Any]):
    text = _format_text(record)
    r = requests.post(webhook_url, json={"text": text}, timeout=15)
    if r.status_code >= 300:
        raise RuntimeError(f"Webhook post failed: {r.text}")


def _send_via_bot(token: str, channel_id: str, record: Dict[str, Any]):
    text = _format_text(record)
    r = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps({"channel": channel_id, "text": text}),
        timeout=15,
    )
    try:
        data = r.json()
    except Exception:
        data = {"ok": False}
    if r.status_code != 200 or not data.get("ok"):
        raise RuntimeError(f"chat.postMessage failed: {r.text}")


def _format_text(rec: Dict[str, Any]) -> str:
    try:
        form_id = rec.get("formId")
        country = rec.get("country") or ""
        submitted_at = rec.get("submittedAt") or ""
        values = rec.get("answers") or {}
        # Pretty print values (key: value)
        parts: List[str] = []
        for k, v in values.items():
            try:
                if isinstance(v, list):
                    vv = ", ".join(str(x) for x in v)
                elif isinstance(v, dict):
                    vv = json.dumps(v, ensure_ascii=False)
                else:
                    vv = str(v)
                parts.append(f"{k}: {vv}")
            except Exception:
                continue
        vals = "\n".join(parts)
        return (
            f"📩 New form submission!\n"
            f"Form ID: {form_id}\n"
            f"Country: {country}\n"
            f"Submitted At: {submitted_at}\n"
            f"Values:\n{vals}"
        )
    except Exception:
        return "📩 New form submission (details unavailable)"


@router.post("/test")
def send_test(userId: str = Query(...), formId: str = Query(...)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Slack integration is available on Pro plans.")
    token, webhook = _get_slack_creds(userId)
    snap = _get_user_doc(userId).get()
    data = snap.to_dict() or {}
    mapping = ((data.get("integrations") or {}).get("slackMappings") or {}).get(formId) or {}
    ch_id = mapping.get("channelId")
    wh_enc = mapping.get("webhook")
    wh = _decrypt(wh_enc) if wh_enc else (webhook or None)
    # Dummy record
    record = {
        "formId": formId,
        "submittedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "country": "US",
        "answers": {"email": "john@example.com", "message": "Hello from CleanEnroll"},
    }
    if wh:
        _send_via_webhook(wh, record)
        return {"sent": True, "via": "webhook"}
    if token and ch_id:
        _send_via_bot(token, ch_id, record)
        return {"sent": True, "via": "bot"}
    raise HTTPException(status_code=400, detail="No Slack delivery method configured (webhook or bot+channel)")


# Helper used by builder.submit_form to push Slack notifications

def try_notify_slack_for_form(user_id: str, form_id: str, record: Dict[str, Any]):
    try:
        if not _is_pro_plan(user_id):
            return
        token, webhook = _get_slack_creds(user_id)
        snap = _get_user_doc(user_id).get()
        data = snap.to_dict() or {}
        mappings = ((data.get("integrations") or {}).get("slackMappings") or {})
        mapping = mappings.get(form_id) or {}
        if not mapping or not mapping.get("synced"):
            return
        # prefer per-form webhook, then global webhook, then bot token + channel
        wh = None
        try:
            if mapping.get("webhook"):
                wh = _decrypt(mapping.get("webhook"))
            elif webhook:
                wh = webhook
        except Exception:
            wh = None
        if wh:
            _send_via_webhook(wh, record)
            return
        ch_id = mapping.get("channelId")
        if token and ch_id:
            _send_via_bot(token, ch_id, record)
            return
    except Exception:
        logger.exception("slack notify error form_id=%s", form_id)
