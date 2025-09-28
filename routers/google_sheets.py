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
from firebase_admin import credentials, firestore

logger = logging.getLogger("backend.google_sheets")

# Initialize Firebase app if not already
if not firebase_admin._apps:
    cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.path.join(os.getcwd(), "cleanenroll-fd36a-firebase-adminsdk-fbsvc-7d79b92b3f.json")
    if not os.path.exists(cred_path):
        raise RuntimeError("Firebase credentials JSON not found; set GOOGLE_APPLICATION_CREDENTIALS")
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()

router = APIRouter(prefix="/api/integrations/google-sheets", tags=["google-sheets"])


def _is_pro_plan(user_id: str) -> bool:
    try:
        snap = db.collection("users").document(user_id).get()
        data = snap.to_dict() or {}
        plan = str(data.get("plan") or "").lower()
        return plan in ("pro", "business", "enterprise")
    except Exception:
        return False

# OAuth config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_SHEETS_REDIRECT_URI = os.getenv("GOOGLE_SHEETS_REDIRECT_URI", "https://api.cleanenroll.com/api/integrations/google-sheets/callback")
FRONTEND_REDIRECT_URL = os.getenv("FRONTEND_REDIRECT_URL", "https://cleanenroll.com/dashboard?integrations=google-sheets&status=connected")
ENCRYPTION_SECRET = (os.getenv("ENCRYPTION_SECRET") or "change-this-secret").encode("utf-8")

SHEETS_BASE = "https://sheets.googleapis.com/v4/spreadsheets"
OAUTH_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
OAUTH_TOKEN = "https://oauth2.googleapis.com/token"

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
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
    return db.collection("users").document(user_id)


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
            # Handle both with and without timezone
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
    doc = _get_user_doc(user_id).get()
    data = doc.to_dict() or {}
    integ = (data.get("integrations") or {}).get("googleSheets") or {}
    tok = integ.get("token")
    rtok = integ.get("refreshToken")
    expiry = int(integ.get("expiry") or 0)
    if not tok:
        raise HTTPException(status_code=400, detail="Google Sheets not connected for this user")
    return _decrypt_token(tok), (_decrypt_token(rtok) if rtok else None), expiry


def _save_tokens(user_id: str, access_token: str, refresh_token: Optional[str], expires_in: Optional[int]):
    enc_access = _encrypt_token(access_token)
    payload: Dict[str, Any] = {"token": enc_access}
    if refresh_token:
        payload["refreshToken"] = _encrypt_token(refresh_token)
    if expires_in:
        payload["expiry"] = int(time.time()) + int(expires_in)
    doc = _get_user_doc(user_id)
    doc.set({"integrations": {"googleSheets": payload}}, merge=True)


def _get_valid_access_token(user_id: str) -> str:
    access, refresh, expiry = _get_tokens(user_id)
    now = int(time.time())
    if expiry and now < (expiry - 60):
        return access
    if not refresh:
        # Try using current access token even if expired
        return access
    # refresh
    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh,
    }
    resp = requests.post(OAUTH_TOKEN, data=data, timeout=15)
    if resp.status_code != 200:
        logger.warning("Google token refresh failed: %s", resp.text)
        return access
    payload = resp.json()
    new_access = payload.get("access_token") or access
    expires_in = payload.get("expires_in")
    # Google may omit refresh_token on refresh
    _save_tokens(user_id, new_access, refresh, expires_in)
    return new_access


@router.get("/authorize")
def authorize(userId: str = Query(...), redirect: Optional[str] = Query(None)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Google Sheets integration is available on Pro plans.")
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")
    state_data = {"userId": userId}
    if redirect:
        state_data["redirect"] = redirect
    state = json.dumps(state_data)
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_SHEETS_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
        "include_granted_scopes": "true",
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
        raise HTTPException(status_code=403, detail="Google Sheets integration is available on Pro plans.")

    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_SHEETS_REDIRECT_URI,
        "grant_type": "authorization_code",
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
        raise HTTPException(status_code=403, detail="Google Sheets integration is available on Pro plans.")
    # Simple connectivity status + mapping for a form if provided
    try:
        access, _, _ = _get_tokens(userId)
        connected = bool(access)
    except Exception:
        connected = False
    mapping = None
    if formId:
        doc = _get_user_doc(userId).get()
        data = doc.to_dict() or {}
        gs_map = ((data.get("integrations") or {}).get("googleSheetsMappings") or {})
        mapping = gs_map.get(formId)
    return {"connected": connected, "mapping": mapping}


@router.post("/create")
def create_sheet(userId: str = Query(...), formId: str = Query(...), payload: Dict[str, Any] = None):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Google Sheets integration is available on Pro plans.")
    if not isinstance(payload, dict):
        payload = {}
    title = (payload.get("title") or "Form Submissions").strip() or "Form Submissions"
    sync_enabled = bool(payload.get("sync"))

    # Build headers and rows from form schema + responses
    form = _read_form_schema(formId)
    fields = form.get("fields") or []
    # Order headers: submittedAt then field labels
    field_order: List[str] = []
    headers: List[str] = ["submittedAt"]
    for f in fields:
        fid = str(f.get("id"))
        label = str(f.get("label") or fid)
        field_order.append(fid)
        headers.append(label)

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

    rows: List[List[str]] = []
    for rec in responses:
        row = [str(rec.get("submittedAt") or "")] + [ _flatten((rec.get("answers") or {}).get(fid)) for fid in field_order ]
        rows.append(row)

    token = _get_valid_access_token(userId)
    # 1) Create spreadsheet
    meta = {"properties": {"title": title}}
    r = requests.post(SHEETS_BASE, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(meta), timeout=20)
    if r.status_code not in (200, 201):
        raise HTTPException(status_code=400, detail=f"Failed to create spreadsheet: {r.text}")
    sp = r.json()
    spreadsheet_id = sp.get("spreadsheetId")
    sheets = sp.get("sheets") or []
    sheet_name = (sheets[0].get("properties", {}).get("title") if sheets else "Sheet1")

    # 2) Write headers + rows
    values = [headers] + rows
    rng = f"{sheet_name}!A1"
    put_url = f"{SHEETS_BASE}/{spreadsheet_id}/values/{requests.utils.quote(rng, safe='')}?valueInputOption=RAW"
    body = {"range": rng, "majorDimension": "ROWS", "values": values}
    r2 = requests.put(put_url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(body), timeout=30)
    if r2.status_code not in (200, 201):
        logger.warning("Initial write failed: %s", r2.text)

    # 3) Save mapping
    doc = _get_user_doc(userId)
    mapping_entry = {
        "spreadsheetId": spreadsheet_id,
        "sheetName": sheet_name,
        "headers": headers,
        "fieldOrder": field_order,
        "synced": sync_enabled,
        "title": title,
    }
    doc.set({"integrations": {"googleSheetsMappings": {formId: mapping_entry}}}, merge=True)

    return {
        "created": True,
        "spreadsheetId": spreadsheet_id,
        "spreadsheetUrl": f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}",
        "sheetName": sheet_name,
        "rows": len(rows),
        "synced": sync_enabled,
    }


@router.post("/sync")
def toggle_sync(userId: str = Query(...), formId: str = Query(...), payload: Dict[str, Any] = None):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Google Sheets integration is available on Pro plans.")
    if not isinstance(payload, dict):
        payload = {}
    desired = bool(payload.get("sync"))
    doc_ref = _get_user_doc(userId)
    snap = doc_ref.get()
    data = snap.to_dict() or {}
    gs_map = ((data.get("integrations") or {}).get("googleSheetsMappings") or {})
    if formId not in gs_map:
        raise HTTPException(status_code=404, detail="No Google Sheets mapping for this form")
    gs_map[formId]["synced"] = desired
    # Write back the entire map to preserve others
    doc_ref.set({"integrations": {"googleSheetsMappings": gs_map}}, merge=True)
    return {"synced": desired}


@router.get("/mappings")
def list_mappings(userId: str = Query(...)):
    """Return all Google Sheets mappings created by this user (formId -> mapping)."""
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Google Sheets integration is available on Pro plans.")
    snap = _get_user_doc(userId).get()
    data = snap.to_dict() or {}
    gs_map = ((data.get("integrations") or {}).get("googleSheetsMappings") or {})
    out: List[Dict[str, Any]] = []
    for form_id, mapping in gs_map.items():
        if not isinstance(mapping, dict):
            continue
        entry = {
            "formId": form_id,
            "title": mapping.get("title") or mapping.get("sheetName") or "Sheet",
            "spreadsheetId": mapping.get("spreadsheetId"),
            "sheetName": mapping.get("sheetName") or "Sheet1",
            "synced": bool(mapping.get("synced")),
            "url": (f"https://docs.google.com/spreadsheets/d/{mapping.get('spreadsheetId')}" if mapping.get("spreadsheetId") else None),
        }
        out.append(entry)
    return {"mappings": out}


# Helper used by builder.submit_form to auto-append new rows when synced

def try_append_submission_for_form(user_id: str, form_id: str, record: Dict[str, Any]):
    try:
        if not _is_pro_plan(user_id):
            return
        # load mapping
        snap = _get_user_doc(user_id).get()
        data = snap.to_dict() or {}
        gs_map = ((data.get("integrations") or {}).get("googleSheetsMappings") or {})
        mapping = gs_map.get(form_id)
        if not mapping or not mapping.get("synced"):
            return
        spreadsheet_id = mapping.get("spreadsheetId")
        sheet_name = mapping.get("sheetName") or "Sheet1"
        field_order: List[str] = mapping.get("fieldOrder") or []
        if not spreadsheet_id or not field_order:
            return
        # build row
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
        row = [str(record.get("submittedAt") or "")] + [ _flatten(answers.get(fid)) for fid in field_order ]
        rng = f"{sheet_name}!A1"
        token = _get_valid_access_token(user_id)
        url = f"{SHEETS_BASE}/{spreadsheet_id}/values/{requests.utils.quote(rng, safe='')}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS"
        body = {"range": rng, "majorDimension": "ROWS", "values": [row]}
        r = requests.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(body), timeout=20)
        if r.status_code not in (200, 201):
            logger.warning("Append to Google Sheet failed: %s", r.text)
    except Exception:
        logger.exception("google_sheets append error form_id=%s", form_id)
