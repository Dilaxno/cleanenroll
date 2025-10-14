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

logger = logging.getLogger("backend.slack")

INTEGRATIONS_BASE = os.path.join(os.getcwd(), "data", "integrations", "slack")
os.makedirs(INTEGRATIONS_BASE, exist_ok=True)

router = APIRouter(prefix="/api/integrations/slack", tags=["slack"]) 


# Plan gate

def _is_pro_plan(user_id: str) -> bool:
    # Without Firestore/Neon plan lookup here, allow by default; enforce via app policy elsewhere if needed.
    return True


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


def _integration_path(user_id: str) -> str:
    return os.path.join(INTEGRATIONS_BASE, f"{user_id}.json")

def _read_integration(user_id: str) -> Dict[str, Any]:
    try:
        with open(_integration_path(user_id), "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _write_integration(user_id: str, payload: Dict[str, Any]) -> None:
    try:
        cur = _read_integration(user_id)
        cur.update(payload or {})
        os.makedirs(INTEGRATIONS_BASE, exist_ok=True)
        with open(_integration_path(user_id), "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=2)
    except Exception:
        logger.exception("Failed to write Slack integration for %s", user_id)


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
        "chat:write.public",
        "incoming-webhook",
        "channels:read",
        "channels:join",
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
    _write_integration(user_id, {"slack": payload})

    target = st.get("redirect") or FRONTEND_REDIRECT_URL
    return RedirectResponse(url=target, status_code=302)


def _get_slack_creds(user_id: str) -> Tuple[Optional[str], Optional[str]]:
    data = _read_integration(user_id)
    integ = (data.get("slack") or {}) if isinstance(data, dict) else {}
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
        data = _read_integration(userId)
        mp = (data.get("slackMappings") or {}) if isinstance(data, dict) else {}
        mapping = mp.get(formId)
    return {"connected": connected, "mapping": mapping}


@router.get("/channels")
def list_channels(userId: str = Query(...), types: Optional[str] = Query(None)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Slack integration is available on Pro plans.")
    token, _ = _get_slack_creds(userId)
    if not token:
        return {"channels": []}
    t = (types or "public_channel").strip()
    url = f"https://slack.com/api/conversations.list?exclude_archived=true&types={t}"
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

    data = _read_integration(userId)
    mappings = (data.get("slackMappings") or {}) if isinstance(data, dict) else {}
    entry: Dict[str, Any] = mappings.get(formId) or {}
    if channel_id:
        entry["channelId"] = channel_id
    if channel_name:
        entry["channelName"] = channel_name
    if webhook_url:
        entry["webhook"] = _encrypt(webhook_url)
    entry["synced"] = sync
    mappings[formId] = entry
    data["slackMappings"] = mappings
    _write_integration(userId, data)
    return {"mapping": {**entry, "webhook": bool(entry.get("webhook"))}}


def _send_via_webhook(webhook_url: str, record: Dict[str, Any]):
    text = _format_text(record)
    r = requests.post(webhook_url, json={"text": text}, timeout=15)
    if r.status_code >= 300:
        raise RuntimeError(f"Webhook post failed: {r.text}")


def _send_via_bot(token: str, channel_id: str, record: Dict[str, Any]):
    text = _format_text(record)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"channel": channel_id, "text": text}

    def _post():
        return requests.post(
            "https://slack.com/api/chat.postMessage",
            headers=headers,
            data=json.dumps(payload),
            timeout=15,
        )

    r = _post()
    try:
        data = r.json()
    except Exception:
        data = {"ok": False}

    if r.status_code == 200 and data.get("ok"):
        return

    # If the bot isn't in the channel yet, try joining and retry once
    if isinstance(data, dict) and data.get("error") == "not_in_channel":
        try:
            requests.post(
                "https://slack.com/api/conversations.join",
                headers=headers,
                data=json.dumps({"channel": channel_id}),
                timeout=15,
            )
        except Exception:
            pass
        r2 = _post()
        try:
            data2 = r2.json()
        except Exception:
            data2 = {"ok": False}
        if r2.status_code == 200 and data2.get("ok"):
            return

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


@router.post("/disconnect")
def disconnect(userId: str = Query(...)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Slack integration is available on Pro plans.")
    data = _read_integration(userId)
    integ = data if isinstance(data, dict) else {}
    # Clear Slack creds and mappings but keep other integrations intact
    integ.pop("slack", None)
    integ.pop("slackMappings", None)
    _write_integration(userId, integ)
    return {"disconnected": True}


@router.post("/test")
def send_test(userId: str = Query(...), formId: str = Query(...)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Slack integration is available on Pro plans.")
    token, webhook = _get_slack_creds(userId)
    data = _read_integration(userId)
    mapping = ((data.get("slackMappings") or {}) if isinstance(data, dict) else {}).get(formId) or {}
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
        data = _read_integration(user_id)
        mappings = (data.get("slackMappings") or {}) if isinstance(data, dict) else {}
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
