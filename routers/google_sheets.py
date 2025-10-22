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

logger = logging.getLogger("backend.google_sheets")

INTEGRATIONS_BASE = os.path.join(os.getcwd(), "data", "integrations", "google_sheets")
os.makedirs(INTEGRATIONS_BASE, exist_ok=True)

router = APIRouter(prefix="/api/integrations/google-sheets", tags=["google-sheets"])


def _is_pro_plan(user_id: str) -> bool:
    # Without Firestore/Neon plan lookup here, allow by default; enforce via app policy elsewhere if needed.
    return True

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
        # shallow merge
        cur.update(payload or {})
        os.makedirs(INTEGRATIONS_BASE, exist_ok=True)
        with open(_integration_path(user_id), "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=2)
    except Exception:
        logger.exception("Failed to write Google Sheets integration for %s", user_id)


async def _read_form_schema(form_id: str) -> Dict[str, Any]:
    """Read form schema from Neon DB."""
    try:
        from db.database import async_session_maker
        from sqlalchemy import text as _text
    except Exception:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                _text("SELECT id, user_id, title, name, fields, theme FROM forms WHERE id = :form_id LIMIT 1"),
                {"form_id": form_id}
            )
            row = result.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Form not found")
            
            return {
                "id": row[0],
                "userId": row[1],
                "title": row[2] or "",
                "name": row[3] or "",
                "fields": row[4] or [],
                "theme": row[5] or {}
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to read form schema from Neon")
        raise HTTPException(status_code=500, detail="Failed to read form")


async def _list_responses(form_id: str) -> List[Dict[str, Any]]:
    """Read form submissions from Neon DB."""
    try:
        from db.database import async_session_maker
        from sqlalchemy import text as _text
    except Exception:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                _text(
                    "SELECT id, data, metadata, submitted_at FROM submissions "
                    "WHERE form_id = :form_id ORDER BY submitted_at ASC"
                ),
                {"form_id": form_id}
            )
            rows = result.fetchall()
            
            items = []
            for row in rows:
                submission = {
                    "id": row[0],
                    "data": row[1] or {},
                    "metadata": row[2] or {},
                    "submittedAt": row[3].isoformat() if row[3] else None
                }
                # Flatten data into submission for compatibility
                if isinstance(submission.get("data"), dict):
                    submission.update(submission["data"])
                items.append(submission)
            
            return items
    except Exception as e:
        logger.exception("Failed to read submissions from Neon")
        return []


def _get_tokens(user_id: str) -> Tuple[str, Optional[str], int]:
    data = _read_integration(user_id)
    integ = (data.get("googleSheets") or {}) if isinstance(data, dict) else {}
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
    _write_integration(user_id, {"googleSheets": payload})


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
    # Simple connectivity status + mappings for a form if provided
    try:
        access, _, _ = _get_tokens(userId)
        connected = bool(access)
    except Exception:
        connected = False
    mappings = []
    sheet_count = 0
    if formId:
        data = _read_integration(userId)
        gs_map = (data.get("googleSheetsMappings") or {}) if isinstance(data, dict) else {}
        # Support both old (single object) and new (array) format
        form_sheets = gs_map.get(formId)
        if isinstance(form_sheets, list):
            mappings = form_sheets
            sheet_count = len(form_sheets)
        elif isinstance(form_sheets, dict):
            # Legacy single mapping - convert to array
            mappings = [form_sheets]
            sheet_count = 1
    return {"connected": connected, "mappings": mappings, "sheetCount": sheet_count}


@router.post("/create")
async def create_sheet(userId: str = Query(...), formId: str = Query(...), payload: Dict[str, Any] = None):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Google Sheets integration is available on Pro plans.")
    if not isinstance(payload, dict):
        payload = {}
    
    # Check sheet limit (10 sheets per user across all forms)
    data = _read_integration(userId)
    if not isinstance(data, dict):
        data = {}
    gs_map = data.get("googleSheetsMappings") or {}
    total_sheets = 0
    for form_id, sheets_data in gs_map.items():
        if isinstance(sheets_data, list):
            total_sheets += len(sheets_data)
        elif isinstance(sheets_data, dict):
            total_sheets += 1
    
    if total_sheets >= 10:
        raise HTTPException(status_code=400, detail="Sheet limit reached. You can create up to 10 Google Sheets total. Delete an existing sheet to create a new one.")
    
    title = (payload.get("title") or "Form Submissions").strip() or "Form Submissions"
    sync_enabled = bool(payload.get("sync"))

    # Build headers and rows from form schema + responses
    form = await _read_form_schema(formId)
    fields = form.get("fields") or []
    # Order headers: submittedAt then field labels
    field_order: List[str] = []
    headers: List[str] = ["submittedAt"]
    for f in fields:
        fid = str(f.get("id"))
        label = str(f.get("label") or fid)
        field_order.append(fid)
        headers.append(label)

    responses = await _list_responses(formId)
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
        # Data is stored with field labels as keys directly in the data object
        # After flattening in _list_responses, field values are accessible by label
        row_values = []
        for idx, fid in enumerate(field_order):
            # Use the header label to get the value (headers are in same order as field_order)
            label = headers[idx + 1] if idx + 1 < len(headers) else None
            value = rec.get(label) if label else None
            row_values.append(_flatten(value))
        row = [str(rec.get("submittedAt") or "")] + row_values
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

    # 3) Save mapping (support multiple sheets per form)
    mapping_entry = {
        "spreadsheetId": spreadsheet_id,
        "sheetName": sheet_name,
        "headers": headers,
        "fieldOrder": field_order,
        "synced": sync_enabled,
        "title": title,
        "createdAt": int(time.time()),
    }
    data = _read_integration(userId)
    if not isinstance(data, dict):
        data = {}
    maps = data.get("googleSheetsMappings") or {}
    if not isinstance(maps, dict):
        maps = {}
    
    # Convert to array format if needed
    existing = maps.get(formId)
    if isinstance(existing, dict):
        # Legacy single mapping - convert to array
        maps[formId] = [existing, mapping_entry]
    elif isinstance(existing, list):
        # Already array - append
        maps[formId] = existing + [mapping_entry]
    else:
        # First sheet for this form
        maps[formId] = [mapping_entry]
    
    data["googleSheetsMappings"] = maps
    _write_integration(userId, data)

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
    data = _read_integration(userId)
    gs_map = (data.get("googleSheetsMappings") or {}) if isinstance(data, dict) else {}
    if formId not in gs_map:
        raise HTTPException(status_code=404, detail="No Google Sheets mapping for this form")
    gs_map[formId]["synced"] = desired
    data["googleSheetsMappings"] = gs_map
    _write_integration(userId, data)
    return {"synced": desired}


@router.get("/mappings")
def list_mappings(userId: str = Query(...)):
    """Return all Google Sheets mappings created by this user (formId -> array of sheets)."""
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Google Sheets integration is available on Pro plans.")
    data = _read_integration(userId)
    gs_map = (data.get("googleSheetsMappings") or {}) if isinstance(data, dict) else {}
    out: List[Dict[str, Any]] = []
    total_count = 0
    
    for form_id, sheets_data in gs_map.items():
        # Support both old (single object) and new (array) format
        sheets_list = []
        if isinstance(sheets_data, list):
            sheets_list = sheets_data
        elif isinstance(sheets_data, dict):
            sheets_list = [sheets_data]
        
        for mapping in sheets_list:
            if not isinstance(mapping, dict):
                continue
            entry = {
                "formId": form_id,
                "title": mapping.get("title") or mapping.get("sheetName") or "Sheet",
                "spreadsheetId": mapping.get("spreadsheetId"),
                "sheetName": mapping.get("sheetName") or "Sheet1",
                "synced": bool(mapping.get("synced")),
                "createdAt": mapping.get("createdAt"),
                "url": (f"https://docs.google.com/spreadsheets/d/{mapping.get('spreadsheetId')}" if mapping.get("spreadsheetId") else None),
            }
            out.append(entry)
            total_count += 1
    
    return {"mappings": out, "totalCount": total_count, "limit": 10}


@router.post("/disconnect")
def disconnect(userId: str = Query(...)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Google Sheets integration is available on Pro plans.")
    data = _read_integration(userId)
    integ = data if isinstance(data, dict) else {}
    # Clear Google Sheets creds and mappings but keep other integrations intact
    integ.pop("googleSheets", None)
    integ.pop("googleSheetsMappings", None)
    _write_integration(userId, integ)
    return {"disconnected": True}

# Helper used by builder.submit_form to auto-append new rows when synced

def try_append_submission_for_form(user_id: str, form_id: str, record: Dict[str, Any]):
    try:
        if not _is_pro_plan(user_id):
            return
        # load mappings (support multiple sheets)
        data = _read_integration(user_id)
        gs_map = (data.get("googleSheetsMappings") or {}) if isinstance(data, dict) else {}
        sheets_data = gs_map.get(form_id)
        
        # Support both old (single object) and new (array) format
        sheets_list = []
        if isinstance(sheets_data, list):
            sheets_list = sheets_data
        elif isinstance(sheets_data, dict):
            sheets_list = [sheets_data]
        
        # Append to all synced sheets for this form
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
        
        for mapping in sheets_list:
            if not mapping or not mapping.get("synced"):
                continue
            spreadsheet_id = mapping.get("spreadsheetId")
            sheet_name = mapping.get("sheetName") or "Sheet1"
            field_order: List[str] = mapping.get("fieldOrder") or []
            headers: List[str] = mapping.get("headers") or []
            if not spreadsheet_id or not field_order:
                continue
            
            # Build row for this sheet using field labels from headers
            # Data is stored with field labels as keys (e.g., {"Full Name": "John", "Email": "john@example.com"})
            row_values = []
            for idx, fid in enumerate(field_order):
                # Use the header label to get the value (headers[0] is 'submittedAt', so offset by 1)
                label = headers[idx + 1] if idx + 1 < len(headers) else None
                value = record.get(label) if label else None
                row_values.append(_flatten(value))
            row = [str(record.get("submittedAt") or "")] + row_values
            rng = f"{sheet_name}!A1"
            token = _get_valid_access_token(user_id)
            url = f"{SHEETS_BASE}/{spreadsheet_id}/values/{requests.utils.quote(rng, safe='')}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS"
            body = {"range": rng, "majorDimension": "ROWS", "values": [row]}
            r = requests.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(body), timeout=20)
            if r.status_code not in (200, 201):
                logger.warning("Append to Google Sheet failed for %s: %s", spreadsheet_id, r.text)
    except Exception:
        logger.exception("google_sheets append error form_id=%s", form_id)
