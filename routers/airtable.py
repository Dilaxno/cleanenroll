import os
import json
import time
import base64
import hmac
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple

import requests
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import RedirectResponse

# Firebase Admin
import firebase_admin
from firebase_admin import credentials  # fix missing import for credentials

logger = logging.getLogger("backend.airtable")

# Initialize Firebase app if not already (not required for storage anymore)
try:
    if not firebase_admin._apps:
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.path.join(os.getcwd(), "cleanenroll-fd36a-firebase-adminsdk-fbsvc-7d79b92b3f.json")
        if os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
except Exception:
    pass

router = APIRouter(prefix="/api/integrations/airtable", tags=["airtable"])

# Filesystem-backed storage for Airtable tokens and mappings
INTEGRATIONS_BASE = os.path.join(os.getcwd(), "data", "integrations", "airtable")
os.makedirs(INTEGRATIONS_BASE, exist_ok=True)

def _path(user_id: str) -> str:
    safe = str(user_id).strip()
    return os.path.join(INTEGRATIONS_BASE, f"{safe}.json")

def _read_integration(user_id: str) -> Dict[str, Any]:
    try:
        with open(_path(user_id), "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _write_integration(user_id: str, payload: Dict[str, Any]) -> None:
    try:
        cur = _read_integration(user_id)
        cur.update(payload or {})
        os.makedirs(INTEGRATIONS_BASE, exist_ok=True)
        with open(_path(user_id), "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=2)
    except Exception:
        logger.exception("Failed to write Airtable integration for %s", user_id)


def _is_pro_plan(user_id: str) -> bool:
    # Without a Neon lookup here, allow by default; plan gating enforced elsewhere.
    return True

# OAuth config
AIRTABLE_CLIENT_ID = os.getenv("AIRTABLE_CLIENT_ID", "")
AIRTABLE_CLIENT_SECRET = os.getenv("AIRTABLE_CLIENT_SECRET", "")
AIRTABLE_REDIRECT_URI = os.getenv("AIRTABLE_REDIRECT_URI", "https://api.cleanenroll.com/api/integrations/airtable/callback")
FRONTEND_REDIRECT_URL = os.getenv("FRONTEND_REDIRECT_URL", "https://cleanenroll.com/dashboard?integrations=airtable&status=connected")
ENCRYPTION_SECRET = (os.getenv("ENCRYPTION_SECRET") or "change-this-secret").encode("utf-8")

OAUTH_AUTH = "https://airtable.com/oauth2/v1/authorize"
OAUTH_TOKEN = "https://airtable.com/oauth2/v1/token"
API_BASE = "https://api.airtable.com/v0"
META_BASE = f"{API_BASE}/meta"

SCOPES = [
    "data.records:read",
    "data.records:write",
    "schema.bases:read",
]


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
    if not hmac.compare_digest(mac, hmac.new(ENCRYPTION_SECRET, raw, hashlib.sha256).digest()):
        raise ValueError("Token MAC verification failed")
    return raw.decode("utf-8")


def _get_user_doc(user_id: str):
    # Deprecated Firestore path; kept for compatibility but unused
    return None


def _read_form_schema(form_id: str) -> Dict[str, Any]:
    path = os.path.join(os.getcwd(), "data", "forms", f"{form_id}.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _list_responses(form_id: str) -> List[Dict[str, Any]]:
    d = os.path.join(os.getcwd(), "data", "responses", form_id)
    items: List[Dict[str, Any]] = []
    if os.path.exists(d):
        for name in os.listdir(d):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(d, name), "r", encoding="utf-8") as f:
                    items.append(json.load(f))
            except Exception:
                continue
    # sort by submittedAt asc
    def _ms(rec: Dict[str, Any]) -> int:
        ts = rec.get("submittedAt") or ""
        try:
            s = str(ts)
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            import datetime
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return int(dt.timestamp() * 1000)
        except Exception:
            return 0
    items.sort(key=_ms)
    return items


def _get_tokens(user_id: str) -> Tuple[str, Optional[str], int]:
    data = _read_integration(user_id)
    integ = (data.get("airtable") or {})
    tok = integ.get("token")
    rtok = integ.get("refreshToken")
    expiry = int(integ.get("expiry") or 0)
    if not tok:
        raise HTTPException(status_code=400, detail="Airtable not connected for this user")
    return _decrypt_token(tok), (_decrypt_token(rtok) if rtok else None), expiry


def _save_tokens(user_id: str, access_token: str, refresh_token: Optional[str], expires_in: Optional[int]):
    enc_access = _encrypt_token(access_token)
    integ = _read_integration(user_id)
    cur = integ.get("airtable") or {}
    cur.update({"token": enc_access})
    if refresh_token:
        cur["refreshToken"] = _encrypt_token(refresh_token)
    if expires_in:
        cur["expiry"] = int(time.time()) + int(expires_in)
    integ["airtable"] = cur
    _write_integration(user_id, integ)


def _get_valid_access_token(user_id: str) -> str:
    access, refresh, expiry = _get_tokens(user_id)
    now = int(time.time())
    if expiry and now < (expiry - 60):
        return access
    if not refresh:
        return access
    # refresh
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh,
        "client_id": AIRTABLE_CLIENT_ID,
        "client_secret": AIRTABLE_CLIENT_SECRET,
    }
    resp = requests.post(OAUTH_TOKEN, data=data, timeout=20)
    if resp.status_code != 200:
        logger.warning("Airtable token refresh failed: %s", resp.text)
        return access
    payload = resp.json()
    new_access = payload.get("access_token") or access
    expires_in = payload.get("expires_in")
    _save_tokens(user_id, new_access, refresh, expires_in)
    return new_access


@router.get("/authorize")
def authorize(userId: str = Query(...), redirect: Optional[str] = Query(None)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    if not AIRTABLE_CLIENT_ID or not AIRTABLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Airtable OAuth not configured")
    state_data = {"userId": userId}
    if redirect:
        state_data["redirect"] = redirect
    state = json.dumps(state_data)
    params = {
        "client_id": AIRTABLE_CLIENT_ID,
        "redirect_uri": AIRTABLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": state,
    }
    from urllib.parse import urlencode, quote_plus
    url = f"{OAUTH_AUTH}?{urlencode(params, quote_via=quote_plus)}"
    return {"authorize_url": url}


@router.get("/callback")
def callback(code: str = Query(None), state: str = Query("{}")):
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
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")

    data = {
        "code": code,
        "grant_type": "authorization_code",
        "client_id": AIRTABLE_CLIENT_ID,
        "client_secret": AIRTABLE_CLIENT_SECRET,
        "redirect_uri": AIRTABLE_REDIRECT_URI,
    }
    resp = requests.post(OAUTH_TOKEN, data=data, timeout=20)
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"OAuth exchange failed: {resp.text}")
    tok = resp.json()
    access_token = tok.get("access_token")
    refresh_token = tok.get("refresh_token")
    expires_in = tok.get("expires_in")
    if not access_token:
        raise HTTPException(status_code=400, detail="OAuth exchange missing access_token")

    _save_tokens(user_id, access_token, refresh_token, expires_in)

    redirect_target = parsed_state.get("redirect") or FRONTEND_REDIRECT_URL
    return RedirectResponse(url=redirect_target, status_code=302)


@router.get("/status")
def status(userId: str = Query(...), formId: Optional[str] = Query(None)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    try:
        access, _, _ = _get_tokens(userId)
        connected = bool(access)
    except Exception:
        connected = False
    mapping = None
    if formId:
        data = _read_integration(userId)
        amap = (data.get("airtableMappings") or {})
        mapping = amap.get(formId)
    return {"connected": connected, "mapping": mapping}


@router.get("/mappings")
def list_mappings(userId: str = Query(...)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    data = _read_integration(userId)
    amap = (data.get("airtableMappings") or {})
    out: List[Dict[str, Any]] = []
    for form_id, mapping in amap.items():
        if not isinstance(mapping, dict):
            continue
        entry = {
            "formId": form_id,
            "title": mapping.get("title") or mapping.get("tableName") or "Airtable",
            "baseId": mapping.get("baseId"),
            "tableId": mapping.get("tableId"),
            "tableName": mapping.get("tableName"),
            "synced": bool(mapping.get("synced")),
            "url": (f"https://airtable.com/{mapping.get('baseId')}/{mapping.get('tableId')}" if mapping.get("baseId") and mapping.get("tableId") else None),
        }
        out.append(entry)
    return {"mappings": out}


@router.post("/link")
def link_table(userId: str = Query(...), formId: str = Query(...), payload: Dict[str, Any] = None):
    """
    Link an existing table or create a new one and optionally backfill.
    Body: {
      baseId: string,
      tableId?: string,
      tableName?: string,
      create?: bool,
      backfill?: bool,
      title?: string,
      sync?: bool
    }
    """
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    if not isinstance(payload, dict):
        payload = {}
    base_id = (payload.get("baseId") or "").strip()
    table_id = (payload.get("tableId") or "").strip()
    table_name = (payload.get("tableName") or "").strip()
    want_create = bool(payload.get("create"))
    want_backfill = bool(payload.get("backfill"))
    sync_enabled = bool(payload.get("sync"))
    title = (payload.get("title") or "Form Submissions").strip() or "Form Submissions"

    if not base_id:
        raise HTTPException(status_code=400, detail="Missing baseId")

    form = _read_form_schema(formId)
    fields = form.get("fields") or []
    field_order: List[str] = []
    headers: List[str] = ["submittedAt"]
    for f in fields:
        fid = str(f.get("id"))
        label = str(f.get("label") or fid)
        field_order.append(fid)
        headers.append(label)

    token = _get_valid_access_token(userId)

    # Resolve or create table
    resolved_table_id = table_id
    resolved_table_name = table_name

    if want_create and not resolved_table_id:
        # Create a new table via Metadata API (best-effort)
        # All fields as singleLineText for simplicity
        schema = {
            "name": resolved_table_name or title,
            "fields": (
                [{"name": headers[0], "type": "singleLineText"}] +
                [{"name": h, "type": "singleLineText"} for h in headers[1:]]
            ),
        }
        url = f"{META_BASE}/bases/{base_id}/tables"
        r = requests.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(schema), timeout=30)
        if r.status_code not in (200, 201):
            logger.warning("Airtable create table failed: %s", r.text)
            raise HTTPException(status_code=400, detail=f"Failed to create Airtable table: {r.text}")
        data = r.json() or {}
        resolved_table_id = data.get("id") or ""
        resolved_table_name = data.get("name") or (resolved_table_name or title)

    if not resolved_table_id:
        # Try to resolve by name via Meta tables list
        try:
            url = f"{META_BASE}/bases/{base_id}/tables"
            r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=20)
            if r.status_code == 200:
                listing = r.json() or {}
                for t in (listing.get("tables") or listing.get("records") or listing.get("data") or []):
                    try:
                        if (str(t.get("name") or "").strip().lower() == (resolved_table_name or title).strip().lower()):
                            resolved_table_id = t.get("id") or ""
                            resolved_table_name = t.get("name") or resolved_table_name or title
                            break
                    except Exception:
                        continue
        except Exception:
            pass
    if not resolved_table_id and not resolved_table_name:
        # Last resort: use provided name (Airtable API supports addressing by name in the path)
        resolved_table_name = table_name or title

    # Save mapping
    mapping_entry = {
        "baseId": base_id,
        "tableId": resolved_table_id or None,
        "tableName": resolved_table_name or None,
        "headers": headers,
        "fieldOrder": field_order,
        "synced": sync_enabled,
        "title": title,
    }
    data = _read_integration(userId)
    amap = data.get("airtableMappings") or {}
    amap[formId] = mapping_entry
    data["airtableMappings"] = amap
    _write_integration(userId, data)

    # Optional backfill
    backfilled = 0
    if want_backfill:
        responses = _list_responses(formId)
        def _flatten(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, list):
                return "; ".join([_flatten(v) for v in val])
            if isinstance(val, dict):
                try:
                    return json.dumps(val, ensure_ascii=False)
                except Exception:
                    return str(val)
            return str(val)
        url_path = (resolved_table_id or resolved_table_name or title)
        post_url = f"{API_BASE}/{base_id}/{requests.utils.quote(url_path, safe='')}"
        # Batch in chunks of 10
        batch: List[Dict[str, Any]] = []
        for rec in responses:
            fields_map = {headers[0]: str(rec.get("submittedAt") or "")}
            ans = rec.get("answers") or {}
            for idx, fid in enumerate(field_order):
                try:
                    fields_map[headers[idx+1]] = _flatten(ans.get(fid))
                except Exception:
                    fields_map[headers[idx+1]] = ""
            batch.append({"fields": fields_map})
            if len(batch) >= 10:
                r = requests.post(post_url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps({"records": batch}), timeout=30)
                if r.status_code not in (200, 201):
                    logger.warning("Airtable backfill batch failed: %s", r.text)
                backfilled += len(batch)
                batch = []
        if batch:
            r = requests.post(post_url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps({"records": batch}), timeout=30)
            if r.status_code not in (200, 201):
                logger.warning("Airtable backfill batch failed: %s", r.text)
            backfilled += len(batch)

    return {
        "linked": True,
        "baseId": base_id,
        "tableId": resolved_table_id,
        "tableName": resolved_table_name,
        "synced": sync_enabled,
        "backfilled": backfilled,
    }


@router.post("/sync")
def toggle_sync(userId: str = Query(...), formId: str = Query(...), payload: Dict[str, Any] = None):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    if not isinstance(payload, dict):
        payload = {}
    desired = bool(payload.get("sync"))
    data = _read_integration(userId)
    amap = (data.get("airtableMappings") or {})
    if formId not in amap:
        raise HTTPException(status_code=404, detail="No Airtable mapping for this form")
    amap[formId]["synced"] = desired
    data["airtableMappings"] = amap
    _write_integration(userId, data)
    return {"synced": desired}


@router.post("/disconnect")
def disconnect(userId: str = Query(...)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    data = _read_integration(userId)
    data.pop("airtable", None)
    data.pop("airtableMappings", None)
    _write_integration(userId, data)
    return {"disconnected": True}

# Helper used by builder.submit_form to auto-append new records when synced

def try_append_submission_for_form(user_id: str, form_id: str, record: Dict[str, Any]):
    try:
        if not _is_pro_plan(user_id):
            return
        data = _read_integration(user_id)
        amap = (data.get("airtableMappings") or {})
        mapping = amap.get(form_id)
        if not mapping or not mapping.get("synced"):
            return
        base_id = mapping.get("baseId")
        table_id = mapping.get("tableId")
        table_name = mapping.get("tableName")
        field_order: List[str] = mapping.get("fieldOrder") or []
        headers: List[str] = mapping.get("headers") or []
        if not base_id or not headers or not field_order:
            return
        def _flatten(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, list):
                return "; ".join([_flatten(v) for v in val])
            if isinstance(val, dict):
                try:
                    return json.dumps(val, ensure_ascii=False)
                except Exception:
                    return str(val)
            return str(val)
        answers = record.get("answers") or {}
        fields_map = {headers[0]: str(record.get("submittedAt") or "")}
        for idx, fid in enumerate(field_order):
            try:
                fields_map[headers[idx+1]] = _flatten(answers.get(fid))
            except Exception:
                fields_map[headers[idx+1]] = ""
        url_path = (table_id or table_name)
        if not url_path:
            return
        post_url = f"{API_BASE}/{base_id}/{requests.utils.quote(url_path, safe='')}"
        token = _get_valid_access_token(user_id)
        body = {"records": [{"fields": fields_map}]}
        r = requests.post(post_url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(body), timeout=20)
        if r.status_code not in (200, 201):
            logger.warning("Append to Airtable failed: %s", r.text)
    except Exception:
        logger.exception("airtable append error form_id=%s", form_id)
