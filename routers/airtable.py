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
from sqlalchemy import text

try:
    from db.database import async_session_maker  # type: ignore
except Exception:
    from ..db.database import async_session_maker  # type: ignore

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

def _integration_path(user_id: str) -> str:
    return os.path.join(INTEGRATIONS_BASE, f"{user_id}.json")

def _pkce_verifier_path(user_id: str) -> str:
    """Temporary storage for PKCE code_verifier during OAuth flow."""
    return os.path.join(INTEGRATIONS_BASE, f"{user_id}_pkce.json")

async def _read_integration(user_id: str) -> Dict[str, Any]:
    """Read Airtable integration data from Neon DB"""
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                text("""
                    SELECT access_token, refresh_token, expires_at, scopes, mappings 
                    FROM airtable_integrations 
                    WHERE uid = :uid
                """),
                {"uid": user_id}
            )
            row = result.fetchone()
            
            if not row:
                return {}
            
            access_token, refresh_token, expires_at, scopes, mappings = row
            
            return {
                "airtable": {
                    "accessToken": access_token,
                    "refreshToken": refresh_token,
                    "expiresAt": expires_at.isoformat() if expires_at else None,
                    "scopes": scopes or []
                },
                "airtableMappings": mappings or {}
            }
    except Exception as e:
        logger.exception(f"Failed to read Airtable integration for {user_id}: {e}")
        return {}

def _save_pkce_verifier(user_id: str, verifier: str) -> None:
    """Store code_verifier temporarily for OAuth callback."""
    try:
        with open(_pkce_verifier_path(user_id), "w", encoding="utf-8") as f:
            json.dump({"verifier": verifier, "timestamp": time.time()}, f)
    except Exception:
        logger.exception("Failed to save PKCE verifier")

def _get_pkce_verifier(user_id: str) -> Optional[str]:
    """Retrieve and delete code_verifier from temporary storage."""
    try:
        path = _pkce_verifier_path(user_id)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Delete after reading (one-time use)
        try:
            os.remove(path)
        except Exception:
            pass
        # Check if not expired (10 minutes)
        if time.time() - data.get("timestamp", 0) > 600:
            return None
        return data.get("verifier")
    except Exception:
        return None

def _generate_pkce_pair() -> Tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge."""
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    return code_verifier, code_challenge

async def _write_integration(user_id: str, payload: Dict[str, Any]) -> None:
    """Write Airtable integration data to Neon DB"""
    try:
        # Read current data
        cur = await _read_integration(user_id)
        cur.update(payload or {})
        
        # Extract OAuth tokens and mappings
        airtable_data = cur.get("airtable") or {}
        access_token = airtable_data.get("accessToken")
        refresh_token = airtable_data.get("refreshToken")
        expires_at = airtable_data.get("expiresAt")
        
        # Convert Unix timestamp to datetime if needed
        if expires_at and isinstance(expires_at, (int, float)):
            from datetime import datetime, timezone
            expires_at = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        
        scopes = airtable_data.get("scopes") or []
        mappings = cur.get("airtableMappings") or {}
        
        async with async_session_maker() as session:
            await session.execute(
                text("""
                    INSERT INTO airtable_integrations 
                    (uid, access_token, refresh_token, expires_at, scopes, mappings, connected_at, updated_at)
                    VALUES (:uid, :access_token, :refresh_token, :expires_at, :scopes, :mappings, NOW(), NOW())
                    ON CONFLICT (uid) DO UPDATE SET
                        access_token = EXCLUDED.access_token,
                        refresh_token = EXCLUDED.refresh_token,
                        expires_at = EXCLUDED.expires_at,
                        scopes = EXCLUDED.scopes,
                        mappings = EXCLUDED.mappings,
                        updated_at = NOW()
                """),
                {
                    "uid": user_id,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_at": expires_at,
                    "scopes": scopes,
                    "mappings": json.dumps(mappings)
                }
            )
            await session.commit()
        
        logger.info(f"Airtable integration written to Neon DB for {user_id}")
    except Exception as e:
        logger.exception("Failed to write Airtable integration for %s", user_id)
        raise HTTPException(status_code=500, detail=f"Failed to save integration data: {str(e)}")


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


async def _get_tokens(user_id: str) -> Tuple[str, Optional[str], int]:
    data = await _read_integration(user_id)
    integ = (data.get("airtable") or {})
    tok = integ.get("accessToken")
    rtok = integ.get("refreshToken")
    expires_at_str = integ.get("expiresAt")
    
    # Convert ISO datetime string to Unix timestamp
    expiry = 0
    if expires_at_str:
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
            expiry = int(dt.timestamp())
        except (ValueError, AttributeError):
            expiry = 0
    
    if not tok:
        raise HTTPException(status_code=400, detail="Airtable not connected for this user")
    return _decrypt_token(tok), (_decrypt_token(rtok) if rtok else None), expiry


async def _save_tokens(user_id: str, access_token: str, refresh_token: Optional[str], expires_in: Optional[int]):
    enc_access = _encrypt_token(access_token)
    integ = await _read_integration(user_id)
    cur = integ.get("airtable") or {}
    cur.update({"accessToken": enc_access})  # Changed from "token" to "accessToken"
    if refresh_token:
        cur["refreshToken"] = _encrypt_token(refresh_token)
    if expires_in:
        cur["expiresAt"] = int(time.time()) + int(expires_in)  # Changed from "expiry" to "expiresAt"
    integ["airtable"] = cur
    await _write_integration(user_id, integ)


async def _get_valid_access_token(user_id: str) -> str:
    access, refresh, expiry = await _get_tokens(user_id)
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
    await _save_tokens(user_id, new_access, refresh, expires_in)
    return new_access


@router.get("/authorize")
async def authorize(userId: str = Query(...), redirect: Optional[str] = Query(None)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    if not AIRTABLE_CLIENT_ID or not AIRTABLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Airtable OAuth not configured")
    
    # Generate PKCE parameters (required by Airtable)
    code_verifier, code_challenge = _generate_pkce_pair()
    _save_pkce_verifier(userId, code_verifier)
    
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
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    from urllib.parse import urlencode, quote_plus
    url = f"{OAUTH_AUTH}?{urlencode(params, quote_via=quote_plus)}"
    logger.info(f"Airtable OAuth initiated for user {userId} with PKCE")
    return {"authorize_url": url}


@router.get("/callback")
async def callback(
    code: str = Query(None), 
    state: str = Query("{}"),
    error: str = Query(None),
    error_description: str = Query(None)
):
    logger.info(f"Airtable callback: code={'present' if code else 'missing'}, state={state[:100] if state else 'empty'}, error={error}")
    
    # Handle OAuth errors (user denied access or other errors)
    if error:
        logger.error(f"Airtable OAuth error: {error}, description: {error_description}")
        # Parse state to get redirect URL
        try:
            parsed_state = json.loads(state or "{}")
            redirect_url = parsed_state.get("redirect", "https://cleanenroll.com/dashboard?integrations=airtable")
        except Exception:
            redirect_url = "https://cleanenroll.com/dashboard?integrations=airtable"
        
        # Redirect back to frontend with error info
        error_msg = error_description or error or "Authorization failed"
        return RedirectResponse(url=f"{redirect_url}&status=error&message={error_msg}", status_code=302)
    
    if not code:
        logger.error("Airtable callback failed: Missing code parameter (and no error parameter)")
        raise HTTPException(status_code=400, detail="Missing code")
    try:
        parsed_state = json.loads(state or "{}")
    except Exception as e:
        logger.error(f"Airtable callback failed: Invalid state JSON - {e}")
        parsed_state = {}
    user_id = parsed_state.get("userId")
    if not user_id:
        logger.error(f"Airtable callback failed: Missing userId in state. Parsed state: {parsed_state}")
        raise HTTPException(status_code=400, detail="Missing userId in state")
    if not _is_pro_plan(str(user_id)):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")

    # Retrieve PKCE code_verifier
    code_verifier = _get_pkce_verifier(user_id)
    if not code_verifier:
        logger.error(f"Airtable callback failed: PKCE verifier not found for user {user_id}")
        raise HTTPException(status_code=400, detail="PKCE verifier expired or not found. Please try connecting again.")

    # Check credentials are loaded
    if not AIRTABLE_CLIENT_ID or not AIRTABLE_CLIENT_SECRET:
        logger.error("Airtable credentials not configured in environment")
        raise HTTPException(status_code=500, detail="Airtable integration not configured")
    
    logger.info(f"Airtable token exchange: client_id={AIRTABLE_CLIENT_ID[:10]}..., redirect_uri={AIRTABLE_REDIRECT_URI}")

    # Airtable requires HTTP Basic Auth for client credentials, not form data
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": AIRTABLE_REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    resp = requests.post(
        OAUTH_TOKEN,
        auth=(AIRTABLE_CLIENT_ID, AIRTABLE_CLIENT_SECRET),
        data=data,
        timeout=20
    )
    if resp.status_code != 200:
        logger.error(f"Airtable OAuth exchange failed: status={resp.status_code}, body={resp.text}")
        raise HTTPException(status_code=400, detail=f"OAuth exchange failed: {resp.text}")
    tok = resp.json()
    access_token = tok.get("access_token")
    refresh_token = tok.get("refresh_token")
    expires_in = tok.get("expires_in")
    if not access_token:
        logger.error(f"Airtable OAuth response missing access_token: {tok}")
        raise HTTPException(status_code=400, detail="OAuth exchange missing access_token")

    await _save_tokens(user_id, access_token, refresh_token, expires_in)
    logger.info(f"Airtable OAuth successful for user {user_id}")

    redirect_target = parsed_state.get("redirect") or FRONTEND_REDIRECT_URL
    return RedirectResponse(url=redirect_target, status_code=302)


@router.get("/status")
async def status(userId: str = Query(...), formId: Optional[str] = Query(None)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    try:
        access, _, _ = await _get_tokens(userId)
        connected = bool(access)
    except Exception:
        connected = False
    mapping = None
    if formId:
        data = await _read_integration(userId)
        amap = (data.get("airtableMappings") or {})
        mapping = amap.get(formId)
    return {"connected": connected, "mapping": mapping}


@router.get("/mappings")
async def list_mappings(userId: str = Query(...)):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    data = await _read_integration(userId)
    amap = (data.get("airtableMappings") or {})
    out: List[Dict[str, Any]] = []
    total_tables = 0
    
    for form_id, mapping_data in amap.items():
        # Support both old format (single dict) and new format (list of dicts)
        mappings = mapping_data if isinstance(mapping_data, list) else [mapping_data]
        
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            
            total_tables += 1
            
            # Construct Airtable URL - use tableId if available, otherwise use tableName
            base_id = mapping.get("baseId")
            table_id = mapping.get("tableId")
            table_name = mapping.get("tableName")
            url = None
            if base_id:
                if table_id:
                    url = f"https://airtable.com/{base_id}/{table_id}"
                elif table_name:
                    # Airtable supports addressing tables by name in URLs
                    url = f"https://airtable.com/{base_id}/{table_name}"
            
            entry = {
                "formId": form_id,
                "title": mapping.get("title") or table_name or "Airtable",
                "baseId": base_id,
                "tableId": table_id,
                "tableName": table_name,
                "synced": bool(mapping.get("synced")),
                "url": url,
            }
            out.append(entry)
    
    return {"mappings": out, "totalCount": total_tables, "limit": 10}


@router.post("/link")
@router.post("/create")  # Alias for frontend compatibility
async def link_table(userId: str = Query(...), formId: str = Query(...), payload: Dict[str, Any] = None):
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
    
    # Check if user has reached the 10 table limit
    data = await _read_integration(userId)
    amap = (data.get("airtableMappings") or {})
    total_tables = 0
    for mapping_data in amap.values():
        if isinstance(mapping_data, list):
            total_tables += len(mapping_data)
        elif isinstance(mapping_data, dict):
            total_tables += 1
    
    # Check if this is an update to existing table or a new table
    existing_mapping = amap.get(formId)
    is_new_table = True
    if existing_mapping:
        if isinstance(existing_mapping, list):
            # Check if table already exists in list
            for m in existing_mapping:
                if isinstance(m, dict) and (m.get("baseId") == base_id and 
                    (m.get("tableId") == table_id or m.get("tableName") == table_name)):
                    is_new_table = False
                    break
        elif isinstance(existing_mapping, dict):
            # Old format - single dict
            if existing_mapping.get("baseId") == base_id and \
               (existing_mapping.get("tableId") == table_id or existing_mapping.get("tableName") == table_name):
                is_new_table = False
    
    if is_new_table and total_tables >= 10:
        raise HTTPException(
            status_code=400, 
            detail=f"Table limit reached ({total_tables}/10 tables). Delete an existing table to create a new one."
        )

    form = await _read_form_schema(formId)
    fields = form.get("fields") or []
    field_order: List[str] = []
    headers: List[str] = ["submittedAt"]
    for f in fields:
        fid = str(f.get("id"))
        label = str(f.get("label") or fid)
        field_order.append(fid)
        headers.append(label)

    token = await _get_valid_access_token(userId)

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

    # Save mapping - support multiple tables per form
    mapping_entry = {
        "baseId": base_id,
        "tableId": resolved_table_id or None,
        "tableName": resolved_table_name or None,
        "headers": headers,
        "fieldOrder": field_order,
        "synced": sync_enabled,
        "title": title,
    }
    
    # Re-read data to get fresh state
    data = await _read_integration(userId)
    amap = data.get("airtableMappings") or {}
    
    # Convert old format (single dict) to new format (list of dicts)
    existing = amap.get(formId)
    if existing is None:
        # No existing mapping, create new list
        amap[formId] = [mapping_entry]
    elif isinstance(existing, dict):
        # Old format - convert to list and check if updating same table
        if existing.get("baseId") == base_id and \
           (existing.get("tableId") == resolved_table_id or existing.get("tableName") == resolved_table_name):
            # Update existing table
            amap[formId] = [mapping_entry]
        else:
            # Add new table to existing
            amap[formId] = [existing, mapping_entry]
    elif isinstance(existing, list):
        # New format - find and update or append
        updated = False
        for i, m in enumerate(existing):
            if isinstance(m, dict) and m.get("baseId") == base_id and \
               (m.get("tableId") == resolved_table_id or m.get("tableName") == resolved_table_name):
                # Update existing table
                existing[i] = mapping_entry
                updated = True
                break
        if not updated:
            # Add new table
            existing.append(mapping_entry)
        amap[formId] = existing
    
    data["airtableMappings"] = amap
    await _write_integration(userId, data)

    # Optional backfill
    backfilled = 0
    if want_backfill:
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
async def toggle_sync(userId: str = Query(...), formId: str = Query(...), payload: Dict[str, Any] = None):
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    if not isinstance(payload, dict):
        payload = {}
    desired = bool(payload.get("sync"))
    data = await _read_integration(userId)
    amap = (data.get("airtableMappings") or {})
    if formId not in amap:
        raise HTTPException(status_code=404, detail="No Airtable mapping for this form")
    amap[formId]["synced"] = desired
    data["airtableMappings"] = amap
    await _write_integration(userId, data)
    return {"synced": desired}


@router.delete("/unlink")
async def unlink_table(
    userId: str = Query(...), 
    formId: str = Query(...),
    baseId: str = Query(None),
    tableId: str = Query(None),
    tableName: str = Query(None)
):
    """Unlink/delete a single Airtable table mapping for a specific form.
    If baseId/tableId/tableName are provided, only that specific table is removed.
    If not provided, all tables for the form are removed (backward compatibility).
    """
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    
    logger.info(f"Unlinking Airtable table for user {userId}, formId {formId}, baseId {baseId}, tableId {tableId}, tableName {tableName}")
    
    # Read current mappings from DB
    data = await _read_integration(userId)
    amap = data.get("airtableMappings") or {}
    
    logger.info(f"Current form mappings before deletion: {list(amap.keys())}")
    
    if formId not in amap:
        logger.warning(f"No mapping found for formId {formId}")
        raise HTTPException(status_code=404, detail="No mapping found for this form")
    
    mapping_data = amap[formId]
    
    # If no specific table identifiers provided, delete all tables for form (backward compatibility)
    if not baseId and not tableId and not tableName:
        del amap[formId]
        logger.info(f"Deleted all tables for formId {formId}")
    else:
        # Delete specific table from the list
        if isinstance(mapping_data, dict):
            # Old format - single table
            if (mapping_data.get("baseId") == baseId or not baseId) and \
               (mapping_data.get("tableId") == tableId or mapping_data.get("tableName") == tableName or (not tableId and not tableName)):
                del amap[formId]
                logger.info(f"Deleted single table for formId {formId}")
            else:
                raise HTTPException(status_code=404, detail="Table not found for this form")
        elif isinstance(mapping_data, list):
            # New format - multiple tables
            original_count = len(mapping_data)
            mapping_data = [m for m in mapping_data if not (
                isinstance(m, dict) and 
                (m.get("baseId") == baseId or not baseId) and
                (m.get("tableId") == tableId or m.get("tableName") == tableName or (not tableId and not tableName))
            )]
            
            if len(mapping_data) == original_count:
                raise HTTPException(status_code=404, detail="Table not found for this form")
            
            if len(mapping_data) == 0:
                # No tables left, remove form entry
                del amap[formId]
                logger.info(f"Deleted last table for formId {formId}, removed form entry")
            else:
                # Update with remaining tables
                amap[formId] = mapping_data
                logger.info(f"Deleted table for formId {formId}, {len(mapping_data)} tables remaining")
    
    logger.info(f"Mappings after deletion: {list(amap.keys())}")
    
    # Directly update DB with JSONB modification for permanent deletion
    async with async_session_maker() as session:
        await session.execute(
            text("""
                UPDATE airtable_integrations 
                SET mappings = :mappings,
                    updated_at = NOW()
                WHERE uid = :uid
            """),
            {
                "uid": userId,
                "mappings": json.dumps(amap)
            }
        )
        await session.commit()
    
    # Verify deletion by reading back from DB
    verification = await _read_integration(userId)
    verify_map = verification.get("airtableMappings") or {}
    
    if formId in verify_map:
        logger.error(f"CRITICAL: FormId {formId} still exists after deletion!")
        raise HTTPException(status_code=500, detail="Failed to delete mapping")
    
    logger.info(f"Successfully unlinked formId {formId} for user {userId} (permanently deleted from Neon DB)")
    return {"unlinked": True, "formId": formId}


@router.post("/unlink-batch")
async def unlink_tables_batch(userId: str = Query(...), payload: Dict[str, Any] = None):
    """Batch delete multiple Airtable table mappings.
    Body: { formIds: ["formId1", "formId2", ...] }
    """
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    if not isinstance(payload, dict):
        payload = {}
    form_ids = payload.get("formIds") or []
    if not isinstance(form_ids, list):
        raise HTTPException(status_code=400, detail="formIds must be an array")
    
    logger.info(f"Batch unlinking {len(form_ids)} Airtable tables for user {userId}")
    
    data = await _read_integration(userId)
    amap = data.get("airtableMappings") or {}
    unlinked = []
    
    for form_id in form_ids:
        if form_id in amap:
            del amap[form_id]
            unlinked.append(form_id)
    
    # Directly update DB for permanent deletion
    async with async_session_maker() as session:
        await session.execute(
            text("""
                UPDATE airtable_integrations 
                SET mappings = :mappings,
                    updated_at = NOW()
                WHERE uid = :uid
            """),
            {
                "uid": userId,
                "mappings": json.dumps(amap)
            }
        )
        await session.commit()
    
    logger.info(f"Successfully batch unlinked {len(unlinked)} tables for user {userId} (permanently deleted from Neon DB)")
    return {"unlinked": unlinked, "count": len(unlinked)}


@router.post("/disconnect")
async def disconnect(userId: str = Query(...)):
    """Disconnect entire Airtable integration (removes all mappings and OAuth tokens)."""
    if not _is_pro_plan(userId):
        raise HTTPException(status_code=403, detail="Airtable integration is available on Pro plans.")
    
    logger.info(f"Disconnecting Airtable integration for user {userId}")
    
    # Delete entire row from Neon DB for permanent removal
    async with async_session_maker() as session:
        await session.execute(
            text("DELETE FROM airtable_integrations WHERE uid = :uid"),
            {"uid": userId}
        )
        await session.commit()
    
    logger.info(f"Successfully disconnected Airtable for user {userId} (permanently deleted from Neon DB)")
    return {"disconnected": True}

# Helper used by builder.submit_form to auto-append new records when synced

async def try_append_submission_for_form(user_id: str, form_id: str, record: Dict[str, Any]):
    try:
        if not _is_pro_plan(user_id):
            return
        data = await _read_integration(user_id)
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
        token = await _get_valid_access_token(user_id)
        body = {"records": [{"fields": fields_map}]}
        r = requests.post(post_url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(body), timeout=20)
        if r.status_code not in (200, 201):
            logger.warning("Append to Airtable failed: %s", r.text)
    except Exception:
        logger.exception("airtable append error form_id=%s", form_id)
