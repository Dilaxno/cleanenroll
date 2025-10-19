# (moved user endpoints below router initialization)
from fastapi import APIRouter, HTTPException, Request, Query, Body
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict
import os
import json
import uuid
import hmac
import hashlib
import base64
import time
import logging
import traceback
from datetime import timedelta
try:
    from standardwebhooks import Webhook  # type: ignore
    _STDWEBHOOKS_AVAILABLE = True
except Exception:
    Webhook = None  # type: ignore
    _STDWEBHOOKS_AVAILABLE = False

logger = logging.getLogger("backend.core")

# Email deliverability validation utilities
try:
    from email_validator import validate_email as _validate_email, EmailNotValidError as _EmailNotValidError  # type: ignore
    _EMAIL_VALIDATOR_AVAILABLE = True
except Exception:
    _EMAIL_VALIDATOR_AVAILABLE = False

try:
    import dns.resolver as _dns_resolver  # type: ignore
    _DNSPY_AVAILABLE = True
except Exception:
    _dns_resolver = None  # type: ignore
    _DNSPY_AVAILABLE = False

# Import reputation helper functions from builder router (Spamhaus/WHOIS/SPF/DMARC/DKIM)
try:
    from routers.builder import _spamhaus_listed, _domain_age_days, _has_spf, _has_dmarc, _has_any_dkim  # type: ignore
    _REPUTATION_HELPERS_AVAILABLE = True
except Exception:
    _spamhaus_listed = None  # type: ignore
    _domain_age_days = None  # type: ignore
    _has_spf = None  # type: ignore
    _has_dmarc = None  # type: ignore
    _has_any_dkim = None  # type: ignore
    _REPUTATION_HELPERS_AVAILABLE = False

# Geo helpers (IP -> country/lat/lon)
try:
    from routers.builder import _geo_from_ip  # type: ignore
    _GEO_HELPERS_AVAILABLE = True
except Exception:
    _geo_from_ip = None  # type: ignore
    _GEO_HELPERS_AVAILABLE = False

# Fuzzy matching for email domain typo suggestions
try:
    from rapidfuzz.distance import Levenshtein as _lev  # type: ignore
    _FUZZY_AVAILABLE = True
except Exception:
    _lev = None  # type: ignore
    _FUZZY_AVAILABLE = False

# Rate limiter shared instance
try:
    from utils.limiter import limiter  # type: ignore
    from utils.limiter import forwarded_for_ip as _ip_from_req  # type: ignore
    from utils.limiter import can_signup_ip as _can_signup_ip, record_signup_ip as _record_signup_ip  # type: ignore
except Exception:
    from utils.limiter import limiter  # type: ignore
    from utils.limiter import forwarded_for_ip as _ip_from_req  # type: ignore
    from utils.limiter import can_signup_ip as _can_signup_ip, record_signup_ip as _record_signup_ip  # type: ignore

try:
    from db.database import async_session_maker
except Exception:
    async_session_maker = None  # type: ignore
    from ..db.database import async_session_maker  # type: ignore

def _mx_lookup(domain: str) -> list[str]:
    """Return list of MX hosts for a domain using dnspython; empty if none or on error."""
    if not _DNSPY_AVAILABLE:
        return []
    try:
        answers = _dns_resolver.resolve(domain, "MX", lifetime=2.0)  # type: ignore
        hosts: list[str] = []
        for rdata in answers:
            try:
                host = str(rdata.exchange).rstrip(".")
                if host:
                    hosts.append(host)
            except Exception:
                continue
        hosts.sort()
        return hosts
    except Exception:
        return []

# Email + Firebase Admin
try:
    # When running as a package (e.g., backend.*)
    from utils.email import render_email, send_email_html  # type: ignore
except Exception:
    # When running flat from repo root
    from utils.email import render_email, send_email_html  # type: ignore
try:
    import firebase_admin
    from utils.firebase_admin_adapter import admin_auth
    _FB_AVAILABLE = True
except Exception:
    firebase_admin = None  # type: ignore
    admin_auth = None  # type: ignore
    admin_credentials = None  # type: ignore
    _FB_AVAILABLE = False

# Firestore has been removed; no FieldFilter or Firestore client is used.

# Temporary/disposable domains cache (in-memory; optional)
TEMP_DOMAINS_CACHE: set[str] = set()
TEMP_DOMAINS_LOADED_AT: float = 0
TEMP_DOMAINS_TTL_SECONDS: int = 600

# Prefer external IsTempMail API for disposable detection when configured
# Returns True if disposable, False if not disposable, None if unknown/error or not configured
def _istempmail_disposable_status(email: str, domain: str) -> bool | None:
    try:
        api_key = os.getenv("ISTEMPMAIL_API_KEY") or os.getenv("IS_TEMPMAIL_API_KEY") or ""
        if not api_key:
            return None
        base = (os.getenv("ISTEMPMAIL_BASE_URL") or "https://api.istempmail.com").rstrip("/")
        # Construct candidate endpoints to maximize compatibility without docs
        paths = [
            f"{base}/v1/email/validate?email=__EMAIL__",
            f"{base}/email/validate?email=__EMAIL__",
            f"{base}/v1/check?email=__EMAIL__",
            f"{base}/check?email=__EMAIL__",
        ]
        from urllib.parse import quote
        encoded = quote(email)
        # Try multiple header styles commonly used by APIs
        header_candidates = [
            {"x-api-key": api_key},
            {"X-API-Key": api_key},
            {"apikey": api_key},
            {"Authorization": f"Bearer {api_key}"},
        ]
        import json as _json
        import urllib.request as _url
        import urllib.error as _err
        def _extract_bool(obj):
            try:
                if obj is None:
                    return None
                # Favor top-level keys
                for k in ("disposable", "temporary", "is_temporary", "isTemporary", "isDisposable"):
                    if isinstance(obj, dict) and k in obj:
                        v = obj.get(k)
                        if isinstance(v, bool):
                            return v
                        # Accept 0/1
                        if isinstance(v, (int, float)):
                            return bool(v)
                        # Accept string "true"/"false"
                        if isinstance(v, str):
                            if v.lower() in ("true", "1", "yes"): return True
                            if v.lower() in ("false", "0", "no"): return False
                # Look into nested common container keys
                for key in ("data", "result", "details"):
                    sub = obj.get(key) if isinstance(obj, dict) else None
                    if isinstance(sub, dict):
                        b = _extract_bool(sub)
                        if b is not None:
                            return b
            except Exception:
                return None
            return None
        for p in paths:
            url = p.replace("__EMAIL__", encoded)
            for headers in header_candidates:
                try:
                    req = _url.Request(url, headers=headers)
                    with _url.urlopen(req, timeout=8) as resp:
                        raw = resp.read().decode("utf-8", errors="ignore")
                        data = None
                        try:
                            data = _json.loads(raw)
                        except Exception:
                            data = None
                        b = _extract_bool(data)
                        if b is not None:
                            return bool(b)
                except _err.HTTPError as e:
                    # 4xx/5xx -> try next variant; do not fail hard
                    continue
                except Exception:
                    continue
        return None
    except Exception:
        return None

async def _ensure_temp_domains_loaded(force: bool = False):
    """
    No-op placeholder. Previously populated from Firestore; now disabled.
    """
    return

router = APIRouter()

# -----------------------------
# User data (Neon)
# -----------------------------

@router.get("/api/user/plan")
@limiter.limit("60/minute")
async def get_user_plan(request: Request, userId: str = Query(..., description="Firebase Auth UID")):
    if not userId:
        raise HTTPException(status_code=400, detail="Missing userId")
    if async_session_maker is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    plan = "free"
    async with async_session_maker() as session:
        try:
            from sqlalchemy import text as _text  # type: ignore
            res = await session.execute(_text("SELECT plan FROM users WHERE uid = :uid LIMIT 1"), {"uid": userId})
            row = res.mappings().first()
            if row and row.get("plan"):
                plan = str(row["plan"]).lower()
        except Exception:
            pass
    return {"userId": userId, "plan": plan}


@router.get("/api/user/info")
@limiter.limit("60/minute")
async def get_user_info(request: Request, userId: str = Query(..., description="Firebase Auth UID")):
    if not userId:
        raise HTTPException(status_code=400, detail="Missing userId")
    if async_session_maker is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    async with async_session_maker() as session:
        from sqlalchemy import text as _text  # type: ignore
        try:
            res = await session.execute(_text(
                """
                SELECT uid, email, display_name, photo_url, plan,
                       forms_count, signup_ip, signup_country,
                       signup_geo_lat, signup_geo_lon, signup_user_agent,
                       signup_at, created_at, updated_at
                FROM users WHERE uid = :uid LIMIT 1
                """
            ), {"uid": userId})
            row = res.mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            data = {k: row[k] for k in row.keys()}
            return {"user": data}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


class UpdateUserProfileRequest(BaseModel):
    displayName: Optional[str] = None
    photoURL: Optional[str] = None


@router.post("/api/user/profile")
@limiter.limit("30/minute")
async def update_user_profile(request: Request, userId: str = Query(..., description="Firebase Auth UID"), req: UpdateUserProfileRequest = None):
    if not userId:
        raise HTTPException(status_code=400, detail="Missing userId")
    if not req:
        raise HTTPException(status_code=400, detail="Missing request body")
    if async_session_maker is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    
    # Build dynamic update query based on provided fields
    updates = []
    params = {"uid": userId}
    
    if req.displayName is not None:
        updates.append("display_name = :display_name")
        params["display_name"] = req.displayName.strip() if req.displayName else None
    
    if req.photoURL is not None:
        updates.append("photo_url = :photo_url")
        params["photo_url"] = req.photoURL.strip() if req.photoURL else None
    
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    updates.append("updated_at = NOW()")
    update_query = f"UPDATE users SET {', '.join(updates)} WHERE uid = :uid"
    
    async with async_session_maker() as session:
        from sqlalchemy import text as _text  # type: ignore
        try:
            await session.execute(_text(update_query), params)
            await session.commit()
            return {"success": True}
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/user/preferences")
@limiter.limit("60/minute")
async def get_user_preferences(request: Request, userId: str = Query(..., description="Firebase Auth UID")):
    if not userId:
        raise HTTPException(status_code=400, detail="Missing userId")
    if async_session_maker is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    async with async_session_maker() as session:
        from sqlalchemy import text as _text  # type: ignore
        res = await session.execute(_text("SELECT preferences, marketing_opt_in FROM users WHERE uid = :uid LIMIT 1"), {"uid": userId})
        row = res.mappings().first()
        prefs = (row or {}).get("preferences") if row else None
        if not isinstance(prefs, dict):
            try:
                import json as _json
                prefs = _json.loads(prefs) if isinstance(prefs, str) else {}
            except Exception:
                prefs = {}
        # Merge Neon marketing_opt_in into preferences.marketingEmails if missing
        try:
            if (row is not None) and ("marketing_opt_in" in row) and ("marketingEmails" not in prefs):
                prefs["marketingEmails"] = bool(row["marketing_opt_in"]) if row["marketing_opt_in"] is not None else False
        except Exception:
            pass
        return {"preferences": prefs or {}}


class UpdatePreferencesRequest(BaseModel):
    preferences: dict


@router.post("/api/user/preferences")
@limiter.limit("30/minute")
async def update_user_preferences(request: Request, userId: str = Query(..., description="Firebase Auth UID"), req: UpdatePreferencesRequest = None):
    if not userId:
        raise HTTPException(status_code=400, detail="Missing userId")
    if not isinstance(req, UpdatePreferencesRequest) or not isinstance(req.preferences, dict):
        raise HTTPException(status_code=400, detail="Invalid preferences payload")
    if async_session_maker is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    async with async_session_maker() as session:
        from sqlalchemy import text as _text  # type: ignore
        try:
            import json as _json
            payload = _json.dumps(req.preferences)
            await session.execute(_text("UPDATE users SET preferences = CAST(:prefs AS JSONB), updated_at = NOW() WHERE uid = :uid"), {"prefs": payload, "uid": userId})
            await session.commit()
            return {"success": True}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


class MarketingOptRequest(BaseModel):
    enabled: bool


@router.post("/api/user/marketing")
@limiter.limit("30/minute")
async def set_marketing_opt_in(request: Request, userId: str = Query(..., description="Firebase Auth UID"), req: MarketingOptRequest = None):
    if not userId:
        raise HTTPException(status_code=400, detail="Missing userId")
    if not isinstance(req, MarketingOptRequest):
        raise HTTPException(status_code=400, detail="Invalid payload")
    if async_session_maker is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    async with async_session_maker() as session:
        from sqlalchemy import text as _text  # type: ignore
        try:
            await session.execute(_text("UPDATE users SET marketing_opt_in = :en, updated_at = NOW() WHERE uid = :uid"), {"en": bool(req.enabled), "uid": userId})
            await session.commit()
            return {"success": True}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

class SignupCheckResponse(BaseModel):
    allowed: bool
    retry_after: int | None = None

@router.options("/api/auth/signup/check")
@router.options("/api/auth/signup/check/")
async def signup_check_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })

@router.get("/api/auth/signup/check", response_model=SignupCheckResponse)
@router.get("/api/auth/signup/check/", response_model=SignupCheckResponse)
async def signup_check(request: Request):
    """Server-side IP-based throttle for account creation.
    Enforces a 24h gap between signups from the same IP.
    Returns {allowed: true} if allowed, else raises 429 with detail.
    """
    # TEMPORARILY DISABLED: IP-based signup rate limiting
    # ip = _ip_from_req(request)
    # allowed, retry = _can_signup_ip(ip, window_hours=24)
    # if not allowed:
    #     raise HTTPException(status_code=429, detail=f"Too many signups from this IP. Try again in {retry} seconds.")
    return {"allowed": True, "retry_after": None}

@router.post("/api/auth/signup/record")
@router.post("/api/auth/signup/record/")
async def signup_record(request: Request):
    """Record a successful signup attempt for the caller IP.
    Should be called only after account creation succeeds to start the 24h window.
    """
    ip = _ip_from_req(request)
    try:
        _record_signup_ip(ip)
    except Exception:
        pass
    return {"status": "ok"}

# -----------------------------
# IPQualityScore Proxy/VPN detection for signup
# -----------------------------

@router.options("/api/abuse/ipqs-check")
@router.options("/api/abuse/ipqs-check/")
async def ipqs_check_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })


@router.get("/api/abuse/ipqs-check")
@router.get("/api/abuse/ipqs-check/")
@limiter.limit("20/minute")
async def ipqs_check(request: Request):
    """Query IPQualityScore for the caller IP and decide if signup should be blocked.
    Returns {allowed: true} when allowed. On block, responds 403 with detail.

    Environment variables:
      - IPQS_API_KEY: required to enable checks. If missing, endpoint allows by default.
      - IPQS_STRICTNESS: optional (0-3), default 1.
      - IPQS_MAX_FRAUD_SCORE: optional (0-100), default 85. Block when fraud_score >= threshold.
    """
    import json as _json
    import urllib.parse as _urlparse
    import urllib.request as _urlreq
    import urllib.error as _urlerr
    import socket as _socket

    api_key = (os.getenv("IPQS_API_KEY") or os.getenv("IPQUALITYSCORE_API_KEY") or "").strip()
    if not api_key:
        # Feature disabled: allow by default
        return {"enabled": False, "allowed": True}

    # Extract client IP and user agent
    ip = _ip_from_req(request) or (getattr(getattr(request, "client", None), "host", "") or "")
    ua = request.headers.get("user-agent") or request.headers.get("User-Agent") or ""
    lang = request.headers.get("accept-language") or request.headers.get("Accept-Language") or ""

    # If IP is local/private or missing, skip strict blocking
    try:
        import ipaddress as _ipaddr
        if not ip:
            return {"enabled": True, "allowed": True, "reason": "no_ip"}
        addr = _ipaddr.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            return {"enabled": True, "allowed": True, "reason": "private_ip"}
    except Exception:
        # Proceed anyway
        pass

    # Compose IPQS request
    try:
        strictness = int(os.getenv("IPQS_STRICTNESS", "1"))
    except Exception:
        strictness = 1
    strictness = max(0, min(3, strictness))
    try:
        max_score = int(os.getenv("IPQS_MAX_FRAUD_SCORE", "85"))
    except Exception:
        max_score = 85

    base = "https://www.ipqualityscore.com/api/json/ip"
    q = {
        "strictness": str(strictness),
        "user_agent": ua,
        "user_language": lang,
        "fast": "1",
    }
    query = _urlparse.urlencode(q)
    url = f"{base}/{api_key}/{_urlparse.quote(ip)}?{query}"

    # Call IPQS with short timeout
    data = None
    try:
        req = _urlreq.Request(url, headers={"Accept": "application/json"})
        with _urlreq.urlopen(req, timeout=6) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            try:
                data = _json.loads(raw)
            except Exception:
                data = None
    except _urlerr.HTTPError as e:
        # Attempt to parse error body
        try:
            raw = e.read().decode("utf-8", errors="ignore")
            data = _json.loads(raw)
        except Exception:
            data = None
    except Exception:
        data = None

    # If API failed, default allow (fail-open) to avoid blocking legit users on transient errors
    if not isinstance(data, dict):
        return {"enabled": True, "allowed": True, "reason": "ipqs_unavailable"}

    # Extract core signals
    def _truthy(v):
        return True if v is True else (str(v).lower() in ("1", "true", "yes") if isinstance(v, (str, int, float)) else False)

    proxy = _truthy(data.get("proxy"))
    vpn = _truthy(data.get("vpn"))
    tor = _truthy(data.get("tor"))
    active_vpn = _truthy(data.get("active_vpn")) or _truthy(data.get("vpn_active"))
    active_tor = _truthy(data.get("active_tor"))
    recent_abuse = _truthy(data.get("recent_abuse"))
    bot = _truthy(data.get("bot_status")) or _truthy(data.get("is_crawler"))
    fraud_score = 0
    try:
        fraud_score = int(data.get("fraud_score") or 0)
    except Exception:
        fraud_score = 0

    reasons: list[str] = []
    blocked = False
    if proxy:
        blocked = True; reasons.append("proxy")
    if vpn or active_vpn:
        blocked = True; reasons.append("vpn")
    if tor or active_tor:
        blocked = True; reasons.append("tor")
    if recent_abuse:
        blocked = True; reasons.append("recent_abuse")
    if bot:
        blocked = True; reasons.append("automation")
    if fraud_score >= max_score:
        blocked = True; reasons.append(f"fraud_score>={max_score}")

    country = data.get("country_code") or data.get("country")

    # Respond according to decision
    if blocked:
        # Keep message user-friendly and actionable
        msg = "Signup blocked due to VPN/proxy or high IP risk. Disable VPN/proxy or try another network."
        # Return 403 to align with frontend's error handling pattern
        raise HTTPException(status_code=403, detail=msg)

    return {
        "enabled": True,
        "allowed": True,
        "ip": ip,
        "country": (str(country).upper() if isinstance(country, str) and country else None),
        "fraud_score": fraud_score,
    }

# -----------------------------
# Signup enrichment (IP + country)
# -----------------------------

@router.options("/api/auth/signup/enrich")
@router.options("/api/auth/signup/enrich/")
async def signup_enrich_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })


@router.post("/api/auth/signup/enrich")
@router.post("/api/auth/signup/enrich/")
async def signup_enrich(request: Request):
    """Record the caller's signup IP and country onto their Neon user row.
    Requires a valid Firebase ID token in the Authorization header.
    """
    # Extract bearer token
    authz = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not authz.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization")
    token = authz.split(" ", 1)[1].strip()

    # Initialize Firebase Admin
    try:
        _ensure_firebase_initialized()
    except HTTPException as e:
        raise HTTPException(status_code=500, detail=f"Firebase initialization failed: {e.detail}")
    # Only require Firebase Auth
    if not (_FB_AVAILABLE and admin_auth is not None):
        raise HTTPException(status_code=500, detail="Firebase Auth unavailable")

    # Verify token -> uid
    try:
        decoded = admin_auth.verify_id_token(token)
        uid = decoded.get("uid")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Determine client IP and geo
    ip = _ip_from_req(request)
    country = None
    lat = None
    lon = None
    try:
        if _geo_from_ip is not None:
            c, la, lo = _geo_from_ip(ip)
            country, lat, lon = (c or None), (la if isinstance(la, (int, float)) else None), (lo if isinstance(lo, (int, float)) else None)
    except Exception:
        country, lat, lon = None, None, None

    # Persist signup metadata to Neon (users table), best-effort
    try:
        async with async_session_maker() as session:
            await session.execute(
                """
                UPDATE users
                SET signup_ip = :ip,
                    signup_country = :country,
                    signup_geo_lat = :lat,
                    signup_geo_lon = :lon,
                    signup_user_agent = :ua,
                    signup_at = NOW(),
                    updated_at = NOW()
                WHERE uid = :uid
                """,
                {
                    "ip": ip or None,
                    "country": (str(country).upper() if isinstance(country, str) and country else None),
                    "lat": lat,
                    "lon": lon,
                    "ua": (request.headers.get("user-agent") or None),
                    "uid": uid,
                },
            )
            await session.commit()
    except Exception:
        # Do not fail the request on storage errors
        pass

    return {"status": "ok", "ip": ip, "country": (str(country).upper() if country else None)}

# -----------------------------
# Signup upsert (create user row in Neon)
# -----------------------------

class SignupUpsertPayload(BaseModel):
    email: Optional[EmailStr] = None
    displayName: Optional[str] = None
    photoURL: Optional[str] = None


@router.options("/api/auth/signup/upsert")
@router.options("/api/auth/signup/upsert/")
async def signup_upsert_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })


@router.post("/api/auth/signup/upsert")
@router.post("/api/auth/signup/upsert/")
async def signup_upsert(request: Request, body: SignupUpsertPayload):
    """Create or update the caller's user row in Neon users table.
    Requires a valid Firebase ID token in the Authorization header.
    """
    # Extract bearer token
    authz = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not authz.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization")
    token = authz.split(" ", 1)[1].strip()

    # Initialize Firebase Admin
    try:
        _ensure_firebase_initialized()
    except HTTPException as e:
        raise HTTPException(status_code=500, detail=f"Firebase initialization failed: {e.detail}")
    if not (_FB_AVAILABLE and admin_auth is not None):
        raise HTTPException(status_code=500, detail="Firebase Auth unavailable")

    # Verify token -> uid, claims email when present
    try:
        decoded = admin_auth.verify_id_token(token)
        uid = decoded.get("uid")
        claim_email = decoded.get("email")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Determine final fields to upsert
    email = (body.email or claim_email) or None
    display_name = (body.displayName or "").strip() or None
    photo_url = (body.photoURL or "").strip() or None

    # Upsert into Neon
    try:
        async with async_session_maker() as session:
            await session.execute(
                _text(
                    """
                    INSERT INTO users (uid, email, display_name, photo_url, created_at, updated_at)
                    VALUES (:uid, :email, :display_name, :photo_url, NOW(), NOW())
                    ON CONFLICT (uid) DO UPDATE SET
                      email = COALESCE(EXCLUDED.email, users.email),
                      display_name = COALESCE(EXCLUDED.display_name, users.display_name),
                      photo_url = COALESCE(EXCLUDED.photo_url, users.photo_url),
                      updated_at = NOW()
                    """
                ),
                {
                    "uid": uid,
                    "email": email,
                    "display_name": display_name,
                    "photo_url": photo_url,
                },
            )
            await session.commit()
    except Exception as e:
        logger.exception("[signup_upsert] Neon upsert failed")
        raise HTTPException(status_code=500, detail="Failed to persist user")

    return {"status": "ok", "uid": uid}

# --- Token helpers for password reset ---
RESET_TOKEN_LEEWAY = 60  # seconds of clock skew allowed

def _verify_reset_token(token: str) -> str:
    """Return email if token valid; raise HTTPException otherwise."""
    try:
        raw = base64.urlsafe_b64decode(token + "==")  # pad
        payload, sig = raw.rsplit(b".", 1)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token format")
    secret = os.getenv("RESET_TOKEN_SECRET", os.getenv("SECRET_KEY", "change-me")).encode("utf-8")
    expected = hmac.new(secret, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=400, detail="Invalid token signature")
    try:
        data = json.loads(payload.decode("utf-8"))
        email = data.get("email")
        exp = int(data.get("exp", 0))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token payload")
    now = int(time.time())
    if now > exp + RESET_TOKEN_LEEWAY:
        raise HTTPException(status_code=400, detail="Token expired")
    if not email:
        raise HTTPException(status_code=400, detail="Invalid token payload")
    return email

# --- Logging helpers ---

def _mask_email(email: str | None) -> str:
  if not email or '@' not in email:
    return str(email)
  local, domain = email.split('@', 1)
  if len(local) <= 2:
    masked_local = (local[:1] + "*") if local else "*"
  else:
    masked_local = local[0] + "***" + local[-1]
  return f"{masked_local}@{domain}"

# Persistence dir (filesystem-based)
DATA_DIR = os.path.join(os.getcwd(), "data", "forms")
os.makedirs(DATA_DIR, exist_ok=True)


class FieldSchema(BaseModel):
    id: str
    label: str
    type: str  # text, number, checkbox, dropdown, date, location
    required: bool = False
    placeholder: Optional[str] = None
    options: Optional[List[str]] = None  # for dropdown/select


class ThemeSchema(BaseModel):
    primaryColor: str = "#4f46e5"
    backgroundColor: str = "#ffffff"
    textColor: str = "#111827"
    inputBgColor: str = "#ffffff"
    inputTextColor: str = "#111827"
    inputBorderColor: str = "#d1d5db"
    inputBorderRadius: int = 8


class FormConfig(BaseModel):
    title: str = "Untitled Form"
    subtitle: str = ""
    theme: ThemeSchema = ThemeSchema()
    fields: List[FieldSchema] = []
    allowedDomains: Optional[List[str]] = None


# -----------------------------
# Auth & Email
# -----------------------------

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirmRequest(BaseModel):
    token: str
    password: str


def _ensure_firebase_initialized():
    if not _FB_AVAILABLE:
        raise HTTPException(status_code=500, detail="Firebase Admin SDK not available on server.")
    if not firebase_admin._apps:  # type: ignore
        # Initialize with GOOGLE_APPLICATION_CREDENTIALS or application default
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        try:
            if cred_path and os.path.exists(cred_path):
                logger.info("Initializing Firebase Admin with service account at %s", cred_path)
                cred = admin_credentials.Certificate(cred_path)
            else:
                logger.info("Initializing Firebase Admin with Application Default Credentials")
                cred = admin_credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred)
            logger.info("Firebase Admin initialized")
        except Exception as e:
            logger.exception("Firebase Admin initialization failed")
            raise HTTPException(status_code=500, detail=f"Failed to initialize Firebase Admin: {e}")


@router.post("/api/auth/password-reset")
@router.post("/api/auth/password-reset/")
async def send_password_reset_email(req: PasswordResetRequest):
    """Generate a Firebase password reset link and email it with our branded template.
    Always return 200 to avoid revealing whether an account exists.
    """
    try:
        _ensure_firebase_initialized()
    except HTTPException:
        # If Firebase Admin is unavailable, don't error-leak; respond 200 but skip send
        logger.warning("Firebase Admin unavailable; skipping password reset email send")
        return {"status": "ok"}

    # Build signed reset token and send branded email to our reset page
    app_base = os.getenv("FRONTEND_URL", "https://cleanenroll.com")
    reset_url = f"{app_base.rstrip('/')}/reset-password"

    # Create a short-lived signed token containing the email and expiry
    secret = os.getenv("RESET_TOKEN_SECRET", os.getenv("SECRET_KEY", "change-me"))
    ttl_seconds = int(os.getenv("RESET_TOKEN_TTL", "900"))  # default 15 minutes
    expires_at = int(time.time()) + ttl_seconds
    payload = json.dumps({"email": req.email, "exp": expires_at}, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload + b"." + sig).decode("utf-8").rstrip("=")

    branded_link = f"{reset_url}?token={token}"

    subject = "Reset your CleanEnroll password"
    html = render_email("base.html", {
        "subject": subject,
        "preheader": "Create a new password to get back into your account.",
        "title": "Reset your password",
        "intro": "Click the button below to open the secure reset page. This link expires in 15 minutes.",
        "content_html": "",
        "cta_label": "Reset Password",
        "cta_url": branded_link,
    })

    try:
        send_email_html(req.email, subject, html)
    except Exception:
        logger.exception("Failed to send password reset email")

    # Always return ok to avoid user enumeration
    logger.info("Password reset responded ok for %s", _mask_email(req.email))
    return {"status": "ok"}

# Explicit CORS preflight handlers
@router.options("/api/auth/password-reset")
@router.options("/api/auth/password-reset/")
async def password_reset_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })

@router.post("/api/auth/password-reset/confirm")
@router.post("/api/auth/password-reset/confirm/")
async def password_reset_confirm(req: PasswordResetConfirmRequest):
    """Verify token, update password in Firebase, and respond success without leaking existence."""
    try:
        _ensure_firebase_initialized()
    except HTTPException:
        logger.warning("Firebase Admin unavailable; skipping password update")
        return {"status": "ok"}

    # Verify token -> email
    try:
        email = _verify_reset_token(req.token)
    except HTTPException as e:
        # Still return ok to avoid enumeration, but log reason
        logger.warning("Password reset confirm failed: %s", e.detail)
        return {"status": "ok"}

    # Lookup user and update password
    try:
        user = admin_auth.get_user_by_email(email)
        admin_auth.update_user(user.uid, password=req.password)
        logger.info("Password updated for %s", _mask_email(email))
        # Send confirmation email (best-effort)
        try:
            when = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.gmtime())
            subject = "Your CleanEnroll password was changed"
            html = render_email("base.html", {
                "subject": subject,
                "preheader": "This is a confirmation that your password was changed.",
                "title": "Password changed",
                "intro": "This is a confirmation that your CleanEnroll password was changed.",
                "content_html": (
                    f"<div><p style='margin:0 0 12px;color:#d1d5db'>If you did not request this change, please contact our support immediately.</p>"
                    f"<p style='margin:0;color:#c7c7c7'>Time (UTC): <strong>{when}</strong></p></div>"
                ),
                "cta_label": "Sign in",
                "cta_url": os.getenv("FRONTEND_URL", "https://cleanenroll.com").rstrip("/") + "/auth",
            })
            send_email_html(email, subject, html)
        except Exception:
            logger.exception("Failed to send password changed confirmation email to %s", _mask_email(email))
    except Exception as ex:
        logger.warning("Password update failed for %s: %s", _mask_email(email), ex)
        # Do not leak details
        return {"status": "ok"}

    return {"status": "ok"}

@router.options("/api/auth/password-reset/confirm")
@router.options("/api/auth/password-reset/confirm/")
async def password_reset_confirm_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })

# -----------------------------
# Email Verification (itsdangerous)
# -----------------------------
class VerifySendRequest(BaseModel):
    email: EmailStr

def _get_verify_serializer():
    try:
        from itsdangerous import URLSafeTimedSerializer  # type: ignore
    except Exception:
        raise HTTPException(status_code=500, detail="Email verification is not configured (itsdangerous missing)")
    secret = os.getenv("EMAIL_VERIFY_SECRET", os.getenv("SECRET_KEY", "change-me"))
    salt = os.getenv("EMAIL_VERIFY_SALT", "email-verify")
    return URLSafeTimedSerializer(secret, salt=salt)

@router.post("/api/auth/verify/send")
@router.post("/api/auth/verify/send/")
async def verify_send(req: VerifySendRequest):
    """Send an email verification link with a 24h signed token.
    Always responds 200 to avoid user enumeration.
    """
    try:
        s = _get_verify_serializer()
        token = s.dumps({"email": req.email})
        app_base = os.getenv("FRONTEND_URL", "https://cleanenroll.com")
        verify_url = f"{app_base.rstrip('/')}/verify?token={token}"
        try:
            ttl = int(os.getenv("EMAIL_VERIFY_TTL", "86400"))  # 24h default
        except Exception:
            ttl = 86400
        ttl_hours = max(1, int(round(ttl / 3600)))

        subject = "Verify your email for CleanEnroll"
        html = render_email("base.html", {
            "subject": subject,
            "preheader": "Confirm your email address to activate your account.",
            "title": "Verify your email",
            "intro": f"Click the button below to confirm your email address. This link expires in {ttl_hours} hours.",
            "content_html": "",
            "cta_label": "Verify Email",
            "cta_url": verify_url,
        })
        try:
            send_email_html(req.email, subject, html)
        except Exception:
            logger.exception("Failed to send verification email")
        return {"status": "ok"}
    except Exception:
        # Do not leak details
        return {"status": "ok"}


@router.options("/api/auth/verify/send")
@router.options("/api/auth/verify/send/")
async def verify_send_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })

# -----------------------------
# Email existence (privacy-preserving, no enumeration)
# -----------------------------
@router.options("/api/auth/email-exists")
@router.options("/api/auth/email-exists/")
async def email_exists_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })

@router.get("/api/auth/email-exists")
@router.get("/api/auth/email-exists/")
@limiter.limit("30/minute")
async def email_exists(request: Request, email: str | None = None):
    """Generic responder for email existence checks.
    Always returns 200 without revealing existence to prevent user enumeration.
    """
    try:
        masked = _mask_email(email)
        logger.info("[email-exists] check for %s", masked)
    except Exception:
        pass
    return {"status": "ok"}


@router.get("/api/auth/verify/confirm")
@router.get("/api/auth/verify/confirm/")
async def verify_confirm(token: str):
    """Confirm email verification from a signed token and mark the user verified.
    Returns JSON status. Frontend can redirect after calling this endpoint.
    """
    try:
        s = _get_verify_serializer()
        try:
            from itsdangerous import BadSignature, SignatureExpired  # type: ignore
        except Exception:
            # Should not happen if serializer import worked
            BadSignature = Exception  # type: ignore
            SignatureExpired = Exception  # type: ignore
        try:
            ttl = int(os.getenv("EMAIL_VERIFY_TTL", "86400"))
        except Exception:
            ttl = 86400
        try:
            data = s.loads(token, max_age=ttl)
        except SignatureExpired:
            return {"status": "expired"}
        except BadSignature:
            return {"status": "invalid"}
        except Exception:
            return {"status": "invalid"}
        email = (data or {}).get("email")
        if not email:
            return {"status": "invalid"}

        # Try to mark verified in Firebase Auth
        try:
            _ensure_firebase_initialized()
        except HTTPException:
            # Continue without failing the confirmation
            pass
        try:
            if _FB_AVAILABLE and admin_auth is not None:
                try:
                    user = admin_auth.get_user_by_email(email)
                    if not getattr(user, "email_verified", False):
                        admin_auth.update_user(user.uid, email_verified=True)
                    # Persist email verified status to Neon users table
                    try:
                        from sqlalchemy import text as _text  # type: ignore
                        from backend.db.database import async_session_maker  # type: ignore
                    except Exception:
                        async_session_maker = None  # type: ignore
                    if async_session_maker is not None:
                        try:
                            async with async_session_maker() as session:
                                # Prefer updating by uid if available; fallback to email match
                                if getattr(user, "uid", None):
                                    await session.execute(
                                        _text("UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE uid = :uid"),
                                        {"uid": user.uid},
                                    )
                                else:
                                    await session.execute(
                                        _text("UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE email = :email"),
                                        {"email": email},
                                    )
                                await session.commit()
                        except Exception:
                            # Do not fail verification if Neon update fails
                            pass
                except Exception:
                    pass
        except Exception:
            pass
        return {"status": "ok"}
    except Exception:
        return {"status": "invalid"}

@router.post("/api/disposable/sync")
@router.post("/api/disposable/sync/")
async def sync_disposable_domains(strict: bool = True):
    """Fetch disposable domain lists from upstream sources and upsert into Neon.
    Table: disposable_domains(domain TEXT PRIMARY KEY, strict BOOLEAN, updated_at TIMESTAMPTZ)
    """
    # Fetch upstream lists
    try:
        import urllib.request as _urlreq
        sources = [
            "https://raw.githubusercontent.com/7c/fakefilter/main/emails/disposable.txt",
            "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
        ]
        domains: set[str] = set()
        for u in sources:
            try:
                with _urlreq.urlopen(u, timeout=10) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
                for line in raw.splitlines():
                    s = line.strip().lower()
                    if not s or s.startswith("#"):
                        continue
                    if s.startswith("@"):
                        s = s[1:]
                    if "/" in s or " " in s:
                        continue
                    if "." in s:
                        domains.add(s)
            except Exception:
                continue
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch error: {e}")

    # Upsert into Neon in batches
    try:
        from sqlalchemy import text as _text  # type: ignore
        async with async_session_maker() as session:
            # Ensure table exists (migration should have created; this is a safety net)
            await session.execute(_text(
                """
                CREATE TABLE IF NOT EXISTS disposable_domains (
                  domain TEXT PRIMARY KEY,
                  strict BOOLEAN DEFAULT TRUE,
                  updated_at TIMESTAMPTZ DEFAULT NOW()
                )
                """
            ))
            batch = []
            count = 0
            for d in domains:
                batch.append((d, bool(strict)))
                if len(batch) >= 500:
                    await session.execute(_text(
                        """
                        INSERT INTO disposable_domains (domain, strict, updated_at)
                        VALUES """ + ",".join(["(:d"+str(i)+", :s"+str(i)+", NOW())" for i in range(len(batch))]) + "\n"
                        + " ON CONFLICT (domain) DO UPDATE SET strict = EXCLUDED.strict, updated_at = NOW()"
                    ), {**{f"d{i}": b[0] for i, b in enumerate(batch)}, **{f"s{i}": b[1] for i, b in enumerate(batch)}})
                    count += len(batch)
                    batch = []
            if batch:
                await session.execute(_text(
                    """
                    INSERT INTO disposable_domains (domain, strict, updated_at)
                    VALUES """ + ",".join(["(:d"+str(i)+", :s"+str(i)+", NOW())" for i in range(len(batch))]) + "\n"
                    + " ON CONFLICT (domain) DO UPDATE SET strict = EXCLUDED.strict, updated_at = NOW()"
                ), {**{f"d{i}": b[0] for i, b in enumerate(batch)}, **{f"s{i}": b[1] for i, b in enumerate(batch)}})
                count += len(batch)
            await session.commit()
        # Optionally refresh in-memory cache
        try:
            TEMP_DOMAINS_CACHE.clear()
            TEMP_DOMAINS_CACHE.update(domains)
        except Exception:
            pass
        return {"status": "ok", "domains": len(domains), "upserted": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upsert error: {e}")

# -----------------------------
# Custom domains API (Caddy on-demand TLS integration)
# -----------------------------
from pydantic import BaseModel as _BaseModel

class LinkCustomDomainRequest(_BaseModel):
    formId: str
    domain: str

@router.post("/api/custom-domain/link")
@router.post("/api/custom-domain/link/")
async def link_custom_domain(req: LinkCustomDomainRequest):
    dom = _normalize_domain(req.domain)
    if not _is_valid_domain(dom):
        raise HTTPException(status_code=400, detail="Invalid domain")
    # Load form and persist pending custom domain with a verification token
    try:
        data = _load_form(req.formId)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Form not found")
    token = data.get("customDomainToken") or uuid.uuid4().hex
    data.update({
        "customDomain": dom,
        "customDomainVerified": False,
        "customDomainToken": token,
    })
    with open(_form_path(req.formId), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    # Return DNS instructions for verification
    return {
        "status": "pending",
        "domain": dom,
        "token": token,
        "verify": {
            "type": "DNS-TXT",
            "name": dom,
            "value": f"ce-verify={token}",
            "note": "Create a TXT record at your domain apex with this exact value, then run verify.",
        }
    }

@router.get("/api/custom-domain/status")
@router.get("/api/custom-domain/status/")
async def custom_domain_status(formId: str):
    try:
        data = _load_form(formId)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Form not found")
    return {
        "domain": data.get("customDomain") or "",
        "verified": bool(data.get("customDomainVerified")),
        "token": data.get("customDomainToken") or "",
    }

class VerifyCustomDomainRequest(_BaseModel):
    formId: str

@router.post("/api/custom-domain/verify")
@router.post("/api/custom-domain/verify/")
async def verify_custom_domain(req: VerifyCustomDomainRequest):
    try:
        data = _load_form(req.formId)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Form not found")
    dom = _normalize_domain(data.get("customDomain") or "")
    if not _is_valid_domain(dom):
        raise HTTPException(status_code=400, detail="No domain linked")
    token = (data.get("customDomainToken") or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="No verification token found")
    # Check TXT records for ce-verify={token}
    txts = _txt_lookup(dom)
    ok = any((f"ce-verify={token}" in (t or "")) for t in txts)
    if not ok:
        # Try common subdomain record name e.g., _ce.<domain>
        txts2 = _txt_lookup(f"_ce.{dom}")
        ok = any((f"ce-verify={token}" in (t or "")) for t in txts2)
    if not ok:
        raise HTTPException(status_code=400, detail="Verification TXT record not found")
    # Mark verified
    data["customDomainVerified"] = True
    with open(_form_path(req.formId), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return {"status": "ok", "verified": True, "domain": dom}

@router.get("/api/allow-domain")
async def allow_domain(domain: str | None = None, request: Request = None):
    """Endpoint for Caddy on_demand_tls ask. Returns 200 if domain is allowed.
    Caddy calls: GET /api/allow-domain?domain=<requested-host>&remote_ip=<ip>
    """
    dom = _normalize_domain(domain or "")
    if not _is_valid_domain(dom):
        return PlainTextResponse("invalid", status_code=403)
    try:
        for name in os.listdir(DATA_DIR):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(DATA_DIR, name), "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("customDomainVerified") and _normalize_domain(str(data.get("customDomain") or "")) == dom:
                    return PlainTextResponse("ok", status_code=200)
            except Exception:
                continue
    except Exception:
        pass
    return PlainTextResponse("denied", status_code=403)

@router.get("/api/validate-email")
@router.get("/api/validate-email/")
@limiter.limit("30/minute")
async def validate_email_deliverability(
    email: str,
    request: Request,
    reputation: bool | int | str = 0,
    min_domain_age: int | None = None,
):
    """Validate email syntax and MX deliverability in real time.
    Returns a JSON payload with syntax_valid, has_mx, deliverable, mx_hosts, and typo suggestion when applicable.
    """
    raw = (email or "").strip()
    result = {
        "input": raw,
        "normalized": "",
        "syntax_valid": False,
        "deliverable": False,
        "has_mx": False,
        "mx_hosts": [],
        "reason": "",
        # Typo suggestion payload
        "typo_suspected": False,
        "suggestion": "",
        "suggestion_domain": "",
        "suggestion_distance": None,
        "disposable": False,
    }
    if not raw:
        result["reason"] = "Email is required"
        return result

    domain = ""

    # Prefer email-validator if available (does syntax + deliverability checks)
    if _EMAIL_VALIDATOR_AVAILABLE:
        try:
            info = _validate_email(raw, check_deliverability=True)  # type: ignore
            result["syntax_valid"] = True
            try:
                result["normalized"] = getattr(info, "normalized", None) or getattr(info, "email", "")  # type: ignore
            except Exception:
                result["normalized"] = raw
            domain = (getattr(info, "domain", "") or getattr(info, "ascii_domain", "") or "")
        except _EmailNotValidError as e:  # type: ignore
            result["reason"] = str(e)
            try:
                domain = raw.split("@", 1)[1]
            except Exception:
                domain = ""
        except Exception as e:
            result["reason"] = f"Validation error: {e}"
            try:
                domain = raw.split("@", 1)[1]
            except Exception:
                domain = ""
    else:
        # Fallback basic syntax check
        if "@" in raw and "." in raw.split("@")[-1]:
            result["syntax_valid"] = True
            try:
                domain = raw.split("@", 1)[1]
            except Exception:
                domain = ""
        else:
            result["reason"] = "Invalid email format"
            return result

    # Explicit MX check via dnspython to surface MX hosts in response
    mx_hosts = _mx_lookup(domain) if domain else []
    result["mx_hosts"] = mx_hosts
    result["has_mx"] = len(mx_hosts) > 0
    result["deliverable"] = bool(result["syntax_valid"] and result["has_mx"])
    # Prefer external IsTempMail API when configured
    try:
        ext = _istempmail_disposable_status(raw, domain)
        if ext is True:
            result["disposable"] = True
            result["deliverable"] = False
            if not result["reason"]:
                result["reason"] = "Disposable email domains are not accepted"
        elif ext is False:
            result["disposable"] = False
    except Exception:
        pass
    # Neon-backed disposable domains check
    try:
        if domain:
            from sqlalchemy import text as _text  # type: ignore
            async with async_session_maker() as session:
                q = _text("SELECT strict FROM disposable_domains WHERE domain = :dom LIMIT 1")
                res = await session.execute(q, {"dom": domain.strip().lower()})
                row = res.mappings().first()
                if row is not None:
                    result["disposable"] = True
                    if bool(row.get("strict")):
                        result["deliverable"] = False
                        if not result.get("reason"):
                            result["reason"] = "Disposable email domains are not accepted"
    except Exception:
        pass

    # Fallback: optional in-memory disposable domains cache (no-op by default)
    try:
        await _ensure_temp_domains_loaded()
        dom_lower = (domain or "").strip().lower()

        if dom_lower and dom_lower in TEMP_DOMAINS_CACHE:
            result["disposable"] = True
            result["deliverable"] = False
            if not result["reason"]:
                result["reason"] = "Disposable email domains are not accepted"
    except Exception:
        pass
    if not result["deliverable"] and not result["reason"]:
        result["reason"] = "No MX records found for domain"

    # Optional reputation checks (Spamhaus/WHOIS/SPF/DMARC/DKIM)
    try:
        rep_flag = False
        if isinstance(reputation, bool):
            rep_flag = reputation
        elif isinstance(reputation, (int, float)):
            rep_flag = bool(reputation)
        elif isinstance(reputation, str):
            rep_flag = reputation.strip().lower() in ("1","true","yes","on")
    except Exception:
        rep_flag = False

    result["reputation_checked"] = False
    if rep_flag and _REPUTATION_HELPERS_AVAILABLE and domain:
        result["reputation_checked"] = True
        try:
            listed = _spamhaus_listed(domain) if _spamhaus_listed else None
        except Exception:
            listed = None
        try:
            age_days = _domain_age_days(domain) if _domain_age_days else None
        except Exception:
            age_days = None
        try:
            spf_ok = _has_spf(domain) if _has_spf else None
        except Exception:
            spf_ok = None
        try:
            dmarc_ok = _has_dmarc(domain) if _has_dmarc else None
        except Exception:
            dmarc_ok = None
        try:
            dkim_ok = _has_any_dkim(domain) if _has_any_dkim else None
        except Exception:
            dkim_ok = None

        result.update({
            "spamhaus_listed": listed,
            "domain_age_days": age_days,
            "spf_ok": spf_ok,
            "dmarc_ok": dmarc_ok,
            "dkim_detected": dkim_ok,
        })

        rep_bad = False
        reasons = []
        try:
            md = int(min_domain_age) if min_domain_age is not None else None
        except Exception:
            md = None
        if listed is True:
            rep_bad = True
            reasons.append("Domain appears on a blocklist")
        if (age_days is not None) and (md is not None) and (age_days < max(1, md)):
            rep_bad = True
            reasons.append(f"Domain is very new ({age_days} days old; minimum {md})")
        if spf_ok is False and dmarc_ok is False:
            rep_bad = True
            reasons.append("Domain lacks SPF and DMARC records")

        result["reputation_bad"] = rep_bad
        if rep_bad:
            result["deliverable"] = False
            if not result.get("reason"):
                result["reason"] = "; ".join(reasons) if reasons else "Email domain has a poor reputation"

    # Smart domain typo detection against common providers using edit distance
    try:
        local_part = raw.split("@", 1)[0] if ("@" in raw) else ""
        dom = (domain or "").lower().strip()
        # Only attempt suggestions when we have a domain part
        if dom:
            COMMON_PROVIDERS = [
                "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "rocketmail.com",
                "outlook.com", "hotmail.com", "live.com", "msn.com", "aol.com",
                "icloud.com", "me.com", "mac.com",
                "protonmail.com", "pm.me",
                "mail.com", "gmx.com", "gmx.net",
                "zoho.com", "yandex.com", "yandex.ru"
            ]
            best = None
            best_dist = 10**9
            if _FUZZY_AVAILABLE:
                for prov in COMMON_PROVIDERS:
                    try:
                        d = _lev.distance(dom, prov)
                        if d < best_dist:
                            best_dist = d
                            best = prov
                    except Exception:
                        continue
            # Suggest when edit distance <= 2 and domain not already exact
            if best and dom != best and best_dist is not None and best_dist <= 2:
                suggestion = f"{local_part}@{best}" if local_part else best
                result["typo_suspected"] = True
                result["suggestion"] = suggestion
                result["suggestion_domain"] = best
                result["suggestion_distance"] = int(best_dist)
    except Exception:
        # Non-fatal; ignore suggestion errors
        pass

    return result

# -----------------------------
# Utility helpers
# -----------------------------

def _form_path(form_id: str) -> str:
    return os.path.join(DATA_DIR, f"{form_id}.json")


def _save_form(data: Dict) -> str:
    form_id = uuid.uuid4().hex
    data_with_id = {**data, "id": form_id}
    with open(_form_path(form_id), "w", encoding="utf-8") as f:
        json.dump(data_with_id, f, ensure_ascii=False, indent=2)
    return form_id


def _load_form(form_id: str) -> Dict:
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise FileNotFoundError
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# -----------------------------
# Custom domains helpers
# -----------------------------

def _normalize_domain(dom: str) -> str:
    try:
        d = (dom or "").strip().lower().strip(".")
        # Remove protocol and path if accidentally included
        if d.startswith("http://"):
            d = d[len("http://"):]
        if d.startswith("https://"):
            d = d[len("https://"):]
        d = d.split("/", 1)[0]
        return d
    except Exception:
        return (dom or "").strip().lower().strip(".")


def _is_valid_domain(dom: str) -> bool:
    d = _normalize_domain(dom)
    if not d or "." not in d:
        return False
    # Basic safe pattern; allow letters, digits, hyphens and dots; 1-63 label length
    import re
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+", d):
        return False
    return True


def _txt_lookup(name: str) -> list[str]:
    if not _DNSPY_AVAILABLE:
        return []
    try:
        answers = _dns_resolver.resolve(name, "TXT", lifetime=2.5)  # type: ignore
        vals: list[str] = []
        for rdata in answers:  # type: ignore
            try:
                # dnspython returns list of strings/bytes per record
                parts = []
                for s in getattr(rdata, 'strings', []) or []:
                    try:
                        parts.append(s.decode('utf-8', errors='ignore'))
                    except Exception:
                        parts.append(str(s))
                if hasattr(rdata, 'strings') and parts:
                    vals.append("".join(parts))
                else:
                    txt = str(rdata.to_text().strip('"'))
                    vals.append(txt)
            except Exception:
                continue
        return vals
    except Exception:
        return []


# -----------------------------
# API (moved from main.py)
# -----------------------------

@router.post("/api/forms")
async def create_form(cfg: FormConfig):
    # Basic type guard for field.type
    allowed_types = {"text", "textarea", "number", "checkbox", "dropdown", "date", "age", "location", "url"}
    for fld in cfg.fields:
        if fld.type not in allowed_types:
            raise HTTPException(status_code=400, detail=f"Unsupported field type: {fld.type}")
        if fld.type == "dropdown" and (not fld.options or len([o for o in fld.options if o.strip()]) == 0):
            raise HTTPException(status_code=400, detail="Dropdown fields require at least one option")

    # Persist
    data = cfg.dict()
    # Normalize allowedDomains and apply defaults when not specified
    try:
        raw = cfg.allowedDomains or []
        norm = []
        seen = set()
        for d in raw:
            try:
                nd = _normalize_domain(d)
            except Exception:
                nd = (d or '').strip().lower()
            if nd and nd not in seen:
                seen.add(nd)
                norm.append(nd)
        if not norm:
            norm = ["cleanenroll.com", "localhost"]
        data["allowedDomains"] = norm
    except Exception:
        data["allowedDomains"] = ["cleanenroll.com", "localhost"]
    form_id = _save_form(data)

    return {
        "id": form_id
    }


@router.get("/api/forms/{form_id}")
async def get_form(form_id: str):
    try:
        data = _load_form(form_id)
        return data
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Form not found")


# -----------------------------
# HTML pages (Builder and Embed)
# -----------------------------

BUILDER_HTML = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>CleanEnroll - Form Builder</title>
  <style>
    :root {
      --bg: #f3f4f6;
      --panel: #ffffff;
      --text: #111827;
      --muted: #6b7280;
      --border: #e5e7eb;
      --primary: #4f46e5;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica Neue, Arial, \"Apple Color Emoji\", \"Segoe UI Emoji\";
      background: var(--bg); color: var(--text);
    }
    .container { display: grid; grid-template-columns: 380px 1fr; gap: 16px; padding: 16px; min-height: 100vh; }
    .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
    .panel h2 { margin: 0 0 12px; font-size: 18px; }
    .section { margin-bottom: 16px; }
    label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
    input[type=text], input[type=number], input[type=color], select, textarea {
      width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; outline: none;
      background: #fff; color: var(--text);
    }
    textarea { resize: vertical; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .fields-list { display: flex; flex-direction: column; gap: 12px; }
    .field-item { border: 1px dashed var(--border); border-radius: 10px; padding: 10px; }
    .field-head { display: flex; gap: 8px; align-items: center; }
    .field-head .grow { flex: 1; }
    .btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border); background: #fff; cursor: pointer; }
    .btn.primary { background: var(--primary); color: white; border-color: var(--primary); }
    .btn.danger { background: #fee2e2; color: #991b1b; border-color: #fecaca; }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .toolbar { display: flex; gap: 8px; align-items: center; justify-content: space-between; margin-bottom: 10px; }

    /* Preview styles */
    .preview-wrap { padding: 8px; }
    .preview { max-width: 720px; margin: 0 auto; background: var(--form-bg, #ffffff); color: var(--form-text, #111827); border-radius: 16px; border: 1px solid var(--border); box-shadow: 0 10px 20px rgba(0,0,0,0.05); }
    .preview .header { padding: 24px; border-bottom: 1px solid var(--border); }
    .preview .header h1 { margin: 0 0 6px; font-size: 24px; }
    .preview .header p { margin: 0; color: var(--muted); }
    .preview .body { padding: 20px 24px; }
    .form-field { margin-bottom: 16px; }
    .form-field label { margin-bottom: 6px; }
    .form-field input[type=text],
    .form-field input[type=number],
    .form-field input[type=date],
    .form-field select,
    .form-field textarea {
      width: 100%; padding: 12px; background: var(--input-bg, #fff); color: var(--input-text, #111827);
      border: 1px solid var(--input-border, #d1d5db); border-radius: var(--radius, 8px);
      outline: none; transition: box-shadow .15s ease, border-color .15s ease;
    }
    .form-field input[type=text]:focus,
    .form-field input[type=number]:focus,
    .form-field input[type=date]:focus,
    .form-field select:focus,
    .form-field textarea:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 4px color-mix(in oklab, var(--primary) 20%, transparent);
    }
    .muted { color: var(--muted); font-size: 12px; }
    .save-box { margin-top: 12px; padding: 12px; border: 1px dashed var(--border); border-radius: 10px; background: #fafafa; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace; }
  </style>
</head>
<body>
  <div class=\"container\">
    <div class=\"panel\">
      <div class=\"toolbar\">
        <h2>Form Settings</h2>
        <button id=\"saveBtn\" class=\"btn primary\">Save & Generate Embed</button>
      </div>

      <div class=\"section\">
        <label>Title</label>
        <input id=\"titleInput\" type=\"text\" placeholder=\"Enter form title\" />
      </div>
      <div class=\"section\">
        <label>Subtitle</label>
        <textarea id=\"subtitleInput\" rows=\"2\" placeholder=\"Enter subtitle/description\"></textarea>
      </div>

      <div class=\"section\">
        <h2>Theme</h2>
        <div class=\"row\">
          <div>
            <label>Primary color</label>
            <input id=\"primaryColor\" type=\"color\" value=\"#4f46e5\" />
          </div>
          <div>
            <label>Background color</label>
            <input id=\"backgroundColor\" type=\"color\" value=\"#ffffff\" />
          </div>
        </div>
        <div class=\"row\">
          <div>
            <label>Text color</label>
            <input id=\"textColor\" type=\"color\" value=\"#111827\" />
          </div>
          <div>
            <label>Input background</label>
            <input id=\"inputBgColor\" type=\"color\" value=\"#ffffff\" />
          </div>
        </div>
        <div class=\"row\">
          <div>
            <label>Input text color</label>
            <input id=\"inputTextColor\" type=\"color\" value=\"#111827\" />
          </div>
          <div>
            <label>Input border color</label>
            <input id=\"inputBorderColor\" type=\"color\" value=\"#d1d5db\" />
          </div>
        </div>
        <div class=\"section\">
          <label>Input border radius (px)</label>
          <input id=\"inputBorderRadius\" type=\"number\" min=\"0\" max=\"30\" value=\"8\" />
        </div>
      </div>

      <div class=\"section\">
        <div class=\"toolbar\">
          <h2>Fields</h2>
          <button id=\"addFieldBtn\" class=\"btn\">+ Add Field</button>
        </div>
        <div id=\"fieldsList\" class=\"fields-list\"></div>
      </div>

      <div id=\"saveBox\" class=\"save-box\" style=\"display:none\">
        <div><strong>Embed code</strong> (copy & paste into your site):</div>
        <pre id=\"iframeCode\" style=\"white-space: pre-wrap; background:#0b1020; color:#d1e7ff; padding:10px; border-radius:8px\"></pre>
        <button id=\"copyIframeBtn\" class=\"btn\">Copy code</button>
        <div class=\"muted\">Paste the script tag into your site where you want the form to appear.</div>
      </div>
    </div>

    <div class=\"panel preview-wrap\">
      <h2>Live Preview</h2>
      <div id=\"preview\"></div>
    </div>
  </div>

<script>
(function(){
  const state = {
    title: 'Untitled Form',
    subtitle: '',
    theme: {
      primaryColor: '#4f46e5',
      backgroundColor: '#ffffff',
      textColor: '#111827',
      inputBgColor: '#ffffff',
      inputTextColor: '#111827',
      inputBorderColor: '#d1d5db',
      inputBorderRadius: 8,
    },
    fields: []
  };

  // Helpers
  function uid(){ return Math.random().toString(36).slice(2,10); }

  function renderPreview(){
    const container = document.getElementById('preview');
    const t = state.theme;
    const styleVars = `--form-bg:${t.backgroundColor};--form-text:${t.textColor};--input-bg:${t.inputBgColor};--input-text:${t.inputTextColor};--input-border:${t.inputBorderColor};--radius:${t.inputBorderRadius}px;--primary:${t.primaryColor}`;

    const header = `
      <div class=\"header\"> 
        <h1>${escapeHtml(state.title || '')}</h1>
        ${state.subtitle ? `<p>${escapeHtml(state.subtitle)}</p>` : ''}
      </div>`;

    const fieldsHtml = state.fields.map(f => renderField(f)).join('');
    container.innerHTML = `
      <div class=\"preview\" style=\"${styleVars}\">${header}<div class=\"body\">${fieldsHtml}</div></div>
    `;
  }

  function escapeHtml(str){
    return String(str).replace(/[&<>\"]/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[s]));
  }

  function renderField(f){
    const req = f.required ? ' <span class=\"muted\">(required)</span>' : '';
    const label = `<label>${escapeHtml(f.label || 'Untitled')}${req}</label>`;
    const ph = f.placeholder ? ` placeholder=\"${escapeHtml(f.placeholder)}\"` : '';
    if (f.type === 'text') {
      const maxAttr = (typeof f.maxLength === 'number' && f.maxLength > 0) ? ` maxlength=\"${f.maxLength}\"` : '';
      return `<div class=\"form-field\">${label}<input type=\"text\"${ph}${maxAttr} /></div>`;
    }
    if (f.type === 'number') {
      return `<div class=\"form-field\">${label}<input type=\"number\"${ph} /></div>`;
    }
    if (f.type === 'checkbox') {
      return `<div class=\"form-field\"><label><input type=\"checkbox\" /> ${escapeHtml(f.label || 'Checkbox')}</label></div>`;
    }
    if (f.type === 'dropdown') {
      const opts = (f.options||[]).map(o => `<option>${escapeHtml(o)}</option>`).join('');
      return `<div class=\"form-field\">${label}<select>${opts}</select></div>`;
    }
    if (f.type === 'textarea') {
      const maxAttr = (typeof f.maxLength === 'number' && f.maxLength > 0) ? ` maxlength=\"${f.maxLength}\"` : '';
      return `<div class=\"form-field\">${label}<textarea rows=\"4\"${ph}${maxAttr}></textarea></div>`;
    }
    if (f.type === 'date') {
      return `<div class=\"form-field\">${label}<input type=\"date\" /></div>`;
    }
    if (f.type === 'location') {
      return `<div class=\"form-field\">${label}
        <div style=\"display:flex; gap:8px;\">
          <input type=\"text\" readonly placeholder=\"Latitude,Longitude\" />
          <button class=\"btn\" type=\"button\">Use my location</button>
        </div>
        <div class=\"muted\">HTML5 Geolocation will be used in the embedded form.</div>
      </div>`;
    }
    return `<div class=\"form-field\">${label}<input type=\"text\"${ph} /></div>`;
  }

  function fieldEditor(f){
    const wrap = document.createElement('div');
    wrap.className = 'field-item';
    wrap.innerHTML = `
      <div class=\"field-head\">
        <input class=\"grow label\" type=\"text\" placeholder=\"Field label\" value=\"${escapeAttr(f.label || '')}\" />
        <select class=\"type\">
          <option value=\"text\" ${f.type==='text'?'selected':''}>Text</option>
          <option value=\"number\" ${f.type==='number'?'selected':''}>Number</option>
          <option value=\"checkbox\" ${f.type==='checkbox'?'selected':''}>Checkbox</option>
          <option value=\"dropdown\" ${f.type==='dropdown'?'selected':''}>Dropdown</option>
          <option value=\"date\" ${f.type==='date'?'selected':''}>Calendar (Date)</option>
          <option value=\"location\" ${f.type==='location'?'selected':''}>Location</option>
        </select>
        <label style=\"display:flex;align-items:center;gap:6px\"><input class=\"required\" type=\"checkbox\" ${f.required?'checked':''}/> required</label>
        <button class=\"btn danger remove\" type=\"button\">Remove</button>
      </div>
      <div class=\"row\" style=\"margin-top:8px\">
        <div><label>Placeholder</label><input class=\"placeholder\" type=\"text\" value=\"${escapeAttr(f.placeholder||'')}\" /></div>
        <div class=\"optsBox\" style=\"display:${f.type==='dropdown'?'block':'none'}\">
          <label>Dropdown options (comma separated)</label>
          <input class=\"options\" type=\"text\" value=\"${escapeAttr((f.options||[]).join(', '))}\" />
        </div>
      </div>
    `;

    const onChange = () => {
      f.label = sel('.label').value;
      f.type = sel('.type').value;
      f.required = sel('.required').checked;
      f.placeholder = sel('.placeholder').value;
      const optsBox = sel('.optsBox');
      if (f.type === 'dropdown') {
        optsBox.style.display = 'block';
        const raw = sel('.options').value || '';
        f.options = raw.split(',').map(s => s.trim()).filter(Boolean);
      } else {
        optsBox.style.display = 'none';
        f.options = [];
      }
      renderPreview();
    };

    function sel(q){ return wrap.querySelector(q); }

    wrap.addEventListener('input', onChange);
    sel('.remove').addEventListener('click', () => {
      state.fields = state.fields.filter(x => x.id !== f.id);
      wrap.remove();
      renderPreview();
    });

    return wrap;
  }

  function renderEditors(){
    const list = document.getElementById('fieldsList');
    list.innerHTML = '';
    state.fields.forEach(f => list.appendChild(fieldEditor(f)));
  }

  function addField(){
    const f = { id: uid(), label: 'Untitled', type: 'text', required: false, placeholder: '' };
    state.fields.push(f);
    renderEditors();
    renderPreview();
  }

  // Inputs
  const bind = (id, keyPath, transform=v=>v) => {
    const el = document.getElementById(id);
    const set = (val) => {
      const keys = keyPath.split('.');
      let obj = state; for (let i=0;i<keys.length-1;i++){ obj = obj[keys[i]]; }
      obj[keys[keys.length-1]] = transform(val);
      renderPreview();
    };
    el.addEventListener('input', e => set(e.target.value));
    if (el.type === 'number') el.addEventListener('change', e => set(e.target.value));
  };

  bind('titleInput','title');
  bind('subtitleInput','subtitle');
  bind('primaryColor','theme.primaryColor');
  bind('backgroundColor','theme.backgroundColor');
  bind('textColor','theme.textColor');
  bind('inputBgColor','theme.inputBgColor');
  bind('inputTextColor','theme.inputTextColor');
  bind('inputBorderColor','theme.inputBorderColor');
  bind('inputBorderRadius','theme.inputBorderRadius', v => parseInt(v||'0',10));

  document.getElementById('addFieldBtn').addEventListener('click', addField);

  // Save
  document.getElementById('saveBtn').addEventListener('click', async () => {
    try {
      const res = await fetch('/api/forms', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(state)
      });
      if (!res.ok) throw new Error('Failed to save form');
      const data = await res.json();
      const formId = data.id;
      const api = window.location.origin;
      const snippet = `<script async src=\"${api}/embed.js\" data-ce-form=\"${formId}\"></script>`;
      document.getElementById('iframeCode').textContent = snippet;
      document.getElementById('saveBox').style.display = 'block';
    } catch (e) {
      alert(e.message || String(e));
    }
  });

  document.getElementById('copyIframeBtn').addEventListener('click', async () => {
    const txt = document.getElementById('iframeCode').textContent;
    try { await navigator.clipboard.writeText(txt); } catch(e) {}
  });

  function escapeAttr(s){ return String(s).replace(/"/g,'&quot;'); }

  // Initial seed
  state.fields = [
    { id: uid(), label: 'Full name', type: 'text', required: true, placeholder: 'Jane Doe' },
    { id: uid(), label: 'Email', type: 'text', required: true, placeholder: 'jane@example.com' },
    { id: uid(), label: 'When can we contact you?', type: 'date', required: false },
    { id: uid(), label: 'How did you hear about us?', type: 'dropdown', options: ['Search', 'Friend', 'Ad'], required: false }
  ];
  document.getElementById('titleInput').value = state.title;
  document.getElementById('subtitleInput').value = state.subtitle;
  renderEditors();
  renderPreview();
})();
</script>
</body>
</html>
"""


@router.get("/")
async def root(request: Request):
    # Host-based custom domain routing -> redirect to form embed when matched
    try:
        host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
        host = (host.split(":")[0] or "").strip().lower().strip(".")
        if host:
            # Scan stored forms for a verified customDomain matching this host
            for name in os.listdir(DATA_DIR):
                if not name.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(DATA_DIR, name), "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if data.get("customDomainVerified") and (str(data.get("customDomain") or "").strip().lower().strip(".") == host):
                        form_id = data.get("id") or name.replace(".json", "")
                        return RedirectResponse(url=f"/form/{form_id}", status_code=307)
                except Exception:
                    continue
    except Exception:
        pass
    # Fallback health/info message
    return PlainTextResponse("app is running")


@router.get("/embed.js")
@router.get("/v1/ce-embed.js")
async def embed_js():
    frontend_url = os.getenv("FRONTEND_URL", "https://cleanenroll.com").rstrip("/")
    js = f"""(function(){{
  try {{
    var d=document,w=window;
    var s=d.currentScript||d.querySelector('script[data-ce-form]');
    if(!s) return;
    var formId=s.getAttribute('data-ce-form')||s.getAttribute('data-form');
    if(!formId) return;
    var origin = s.getAttribute('data-ce-origin') || '{frontend_url}';
    var pageHost = (window.location && window.location.hostname) ? window.location.hostname : '';
    var src = origin.replace(/\/$/,'') + '/form/' + encodeURIComponent(formId) + '?embed=1' + (pageHost ? '&host=' + encodeURIComponent(pageHost) : '');
    var container = d.createElement('div');
    container.className='ce-embed';
    var iframe = d.createElement('iframe');
    iframe.src = src;
    iframe.loading='lazy';
    iframe.referrerPolicy='no-referrer-when-downgrade';
    iframe.style.width='100%';
    iframe.style.minHeight='700px';
    iframe.style.border='0';
    container.appendChild(iframe);
    s.parentNode.insertBefore(container, s.nextSibling);
  }} catch(e) {{}}
}})();"""
    return PlainTextResponse(js, media_type="application/javascript", headers={"Cache-Control": "public, max-age=86400"})


# --------------
# SPA route redirect helpers
# --------------
@router.get("/form/{form_id}", response_class=HTMLResponse)
async def serve_form_backend(form_id: str):
    """Serve /form/{form_id} directly from the backend with headers that allow embedding anywhere.
    This avoids relying on frontend redirects and ensures XFO/CSP are set permissively for embeds.
    """
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Form {form_id}</title>
</head>
<body>
  <div id="ce-embed"></div>
  <script async src="/embed.js" data-ce-form="{form_id}"></script>
</body>
</html>"""
    resp = HTMLResponse(content=html)
    # Allow embedding by clearing XFO and setting permissive frame-ancestors
    resp.headers["X-Frame-Options"] = ""
    resp.headers["Content-Security-Policy"] = "frame-ancestors *;"
    return resp

@router.get("/form/{path:path}")
async def spa_form_redirect(path: str, request: Request):
    """Redirect SPA /form/* paths to the frontend app to avoid 404s on the API server.
    Set FRONTEND_URL (e.g., https://cleanenroll.com) so the API can redirect.
    """
    frontend = os.getenv("FRONTEND_URL")
    if frontend:
        # Avoid self-redirect loops when FRONTEND_URL points to the same host as this API
        try:
            from urllib.parse import urlparse
            fh = (urlparse(frontend).hostname or "").strip().lower().strip(".")
            if not fh:
                # Fallback: strip protocol manually
                fh = frontend.replace("https://", "").replace("http://", "").split("/", 1)[0].strip().lower().strip(".")
        except Exception:
            fh = frontend.replace("https://", "").replace("http://", "").split("/", 1)[0].strip().lower().strip(".")
        req_host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(":", 1)[0].strip().lower().strip(".")
        if fh and fh == req_host:
            # Serve a small OK response instead of redirecting to ourselves
            return PlainTextResponse("Form route handled by frontend; avoiding self-redirect", status_code=200)
        url = f"{frontend.rstrip('/')}/form/{path}"
        return RedirectResponse(url, status_code=307)
    return PlainTextResponse(
        "This path is handled by the frontend SPA. Set FRONTEND_URL to enable redirects.",
        status_code=404,
    )

@router.head("/form/{path:path}")
async def spa_form_head(path: str):
    # Allow HEAD requests to succeed (used by curl -I, proxies, and health checks)
    return PlainTextResponse("", status_code=204)

@router.options("/form/{path:path}")
async def spa_form_options(path: str):
    # Allow CORS preflight or proxy OPTIONS checks
    return PlainTextResponse(
        "",
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        },
    )

# --------------
# Health endpoint
# --------------
@router.get("/health")
async def health():
    return {"status": "ok"}


# -----------------------------
# Dodo Payments Webhook
# -----------------------------
# Accept both legacy and provider default paths
@router.post("/api/webhooks/dodo")
@router.post("/api/payments/dodo/webhook")
@router.post("/api/payments/dodo/webhook/")
async def dodo_webhook(request: Request):
    """Handle Dodo Payments webhook events.
    When subscription is active/renewed or a payment succeeds, set user's plan to 'pro' in Neon.
    When subscription is cancelled, set plan to 'free'.
    UID resolution priority: metadata.user_uid -> query_params.user_uid -> lookup by customer email in Neon.
    """
    # Read raw body (for signature verification if needed later)
    try:
        raw_body = await request.body()
        raw_text = raw_body.decode('utf-8', errors='replace')
        logger.info("[dodo-webhook] received: body_len=%d", len(raw_text))
    except Exception:
        logger.exception("[dodo-webhook] failed to read body")
        raise HTTPException(status_code=400, detail="Invalid body")

    # Verify Standard Webhooks signature from Dodo
    headers = request.headers
    webhook_id = headers.get('webhook-id')
    # Support alternate provider header names for signature
    webhook_sig = (
        headers.get('webhook-signature')
        or headers.get('dodo-signature')
        or headers.get('x-dodo-signature')
        or headers.get('signature')
    )
    webhook_ts = headers.get('webhook-timestamp') or headers.get('webhook-time') or headers.get('timestamp')
    secret = os.getenv('DODO_WEBHOOK_SECRET') or os.getenv('DODO_PAYMENTS_WEBHOOK_KEY')

    logger.debug("[dodo-webhook] headers present: id=%s ts=%s sig=%s secret=%s", bool(webhook_id), bool(webhook_ts), bool(webhook_sig), bool(secret))
    if not (webhook_id and webhook_sig and webhook_ts and secret):
        logger.warning("[dodo-webhook] missing required headers or secret; rejecting")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Timestamp tolerance (default 5 minutes)
    try:
        ts = int(str(webhook_ts))
        now = int(time.time())
        tolerance = int(os.getenv('DODO_WEBHOOK_TOLERANCE', '300'))
        delta = now - ts
        logger.debug("[dodo-webhook] timestamp check: now=%s ts=%s delta=%ss tolerance=%ss", now, ts, delta, tolerance)
        if abs(delta) > tolerance:
            logger.warning("[dodo-webhook] timestamp outside tolerance; rejecting")
            raise HTTPException(status_code=401, detail="Webhook timestamp outside tolerance")
    except ValueError:
        logger.warning("[dodo-webhook] invalid timestamp header; rejecting")
        raise HTTPException(status_code=401, detail="Invalid webhook timestamp")

    # Enforce Standard Webhooks library usage only
    if not _STDWEBHOOKS_AVAILABLE:
        logger.error("[dodo-webhook] standardwebhooks library is not available on server")
        raise HTTPException(status_code=500, detail="Webhook verification library unavailable")

    try:
        wh = Webhook(secret)
        std_headers = {
            "webhook-id": webhook_id,
            "webhook-signature": headers.get('webhook-signature') or headers.get('dodo-signature') or headers.get('x-dodo-signature') or headers.get('signature') or "",
            "webhook-timestamp": str(webhook_ts),
        }
        # standardwebhooks expects the exact stringified payload
        wh.verify(raw_text, std_headers)
        logger.info("[dodo-webhook] signature verified via standardwebhooks")
    except Exception:
        logger.warning("[dodo-webhook] signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Idempotency: check if webhook-id already processed
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                "SELECT webhook_id FROM webhooks_idempotency WHERE webhook_id = :wid",
                {"wid": webhook_id},
            )
            if res.first():
                logger.info("[dodo-webhook] duplicate webhook-id=%s already processed; skipping", webhook_id)
                return {"status": "ok", "duplicate": True}
    except Exception:
        # Do not block on idempotency storage issues
        logger.exception("[dodo-webhook] idempotency pre-check failed")

    # Parse JSON after verification
    try:
        payload = json.loads(raw_text)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Extract event type (support multiple keys)
    event_type = (
        payload.get("event_type")
        or payload.get("type")
        or payload.get("eventType")
    )
    if not event_type:
        logger.info("[dodo-webhook] missing event type; ignoring")
        return {"status": "ignored", "reason": "missing event type"}

    # Process subscription lifecycle and initial payment events
    logger.info("[dodo-webhook] event_type=%s", event_type)
    handled_events = {
        "subscription.active",
        "subscription.renewed",
        "subscription.cancelled",
        "subscription.on_hold",
        "subscription.failed",
        "subscription.expired",
        "payment.succeeded",
    }
    if event_type not in handled_events:
        logger.info("[dodo-webhook] ignoring event_type=%s", event_type)
        return {"status": "ok", "event_type": event_type}

    data = payload.get("data", {}) or {}
    metadata = (
        data.get("metadata")
        or data.get("meta")
        or payload.get("metadata")
        or payload.get("meta")
        or {}
    )
    query_params = data.get("query_params", {}) or {}

    # Support flattened metadata keys like metadata_user_uid, metadata_plan
    if (not isinstance(metadata, dict)) or (not metadata):
        try:
            def _extract_flat_metadata(container: dict) -> dict:
                md: dict = {}
                if isinstance(container, dict):
                    for k, v in container.items():
                        if isinstance(k, str) and k.startswith("metadata_"):
                            key = k[len("metadata_"):]
                            if key:
                                md[key] = v
                return md
            flat_meta = _extract_flat_metadata(data)
            if not flat_meta:
                flat_meta = _extract_flat_metadata(payload)
            if flat_meta:
                metadata = {**(metadata if isinstance(metadata, dict) else {}), **flat_meta}
                logger.debug("[dodo-webhook] reconstructed metadata from flattened keys: %s", list(metadata.keys()))
        except Exception:
            pass

    # Attempt to derive identifiers (prefer explicit UID over email)
    def _first_key(d: dict, keys: list[str]):
        for k in keys:
            if isinstance(d, dict) and d.get(k) is not None:
                try:
                    v = str(d.get(k)).strip()
                except Exception:
                    v = d.get(k)
                if v:
                    return v
        return None

    uid_keys = ["user_uid", "uid", "userId", "firebase_uid", "user_id", "userUID", "userUid", "firebaseUid"]
    user_id = _first_key(metadata, uid_keys) or _first_key(query_params, uid_keys)

    def _find_email(obj):
        try:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    try:
                        key = str(k).lower()
                    except Exception:
                        key = ""
                    if "email" in key and isinstance(v, str) and "@" in v:
                        return v.strip()
                    res = _find_email(v)
                    if res:
                        return res
            elif isinstance(obj, list):
                for it in obj:
                    res = _find_email(it)
                    if res:
                        return res
        except Exception:
            pass
        return None

    customer = data.get("customer") or {}
    customer_email = None
    if isinstance(customer, dict):
        customer_email = (
            customer.get("email")
            or customer.get("customer_email")
            or customer.get("customerEmail")
            or (customer.get("details", {}) or {}).get("email")
        )
    if not customer_email:
        customer_email = (
            data.get("customer_email")
            or data.get("customerEmail")
            or data.get("email")
            or (metadata.get("email") if isinstance(metadata, dict) else None)
            or (metadata.get("customer_email") if isinstance(metadata, dict) else None)
            or (metadata.get("customerEmail") if isinstance(metadata, dict) else None)
            or (query_params.get("email") if isinstance(query_params, dict) else None)
            or (query_params.get("customer_email") if isinstance(query_params, dict) else None)
            or (query_params.get("customerEmail") if isinstance(query_params, dict) else None)
        )
    if not customer_email:
        customer_email = _find_email(payload)
    if isinstance(customer_email, str):
        customer_email = customer_email.strip()

    # Collect some reference ids for audit
    subscription_id = (
        data.get("subscription_id")
        or (data.get("subscription") or {}).get("subscription_id")
    )
    product_id = data.get("product_id") or (data.get("product") or {}).get("product_id")
    payment_id = data.get("payment_id") or data.get("id") or payload.get("id")

    # Resolve UID (try metadata/query_params, then fallback via Neon select by email)
    resolved_uid = None
    if user_id:
        logger.info("[dodo-webhook] uid found in metadata/query_params")
        resolved_uid = user_id
    else:
        # Fallback: try mapping by customer email using Neon
        if customer_email:
            try:
                async with async_session_maker() as session:
                    res = await session.execute(
                        "SELECT uid FROM users WHERE LOWER(email) = LOWER(:email) LIMIT 1",
                        {"email": customer_email},
                    )
                    row = res.first()
                    if row and row[0]:
                        resolved_uid = row[0]
                        logger.info("[dodo-webhook] resolved uid via Neon by email")
            except Exception:
                resolved_uid = None

    # Determine plan baseline (override to free for terminal cancellation states)
    plan = (
        (metadata.get("plan") if isinstance(metadata, dict) else None)
        or (query_params.get("plan") if isinstance(query_params, dict) else None)
        or "pro"
    )
    new_plan = plan
    if event_type in ("subscription.cancelled", "subscription.expired", "subscription.failed"):
        new_plan = "free"

    # Update user plan in Neon if we have a uid and a planned change
    try:
        if resolved_uid and new_plan:
            async with async_session_maker() as session:
                await session.execute(
                    "UPDATE users SET plan = :plan, updated_at = NOW() WHERE uid = :uid",
                    {"plan": new_plan, "uid": resolved_uid},
                )
                # Record idempotency only after a successful plan update
                try:
                    await session.execute(
                        """
                        INSERT INTO webhooks_idempotency (webhook_id, event_type, user_uid, customer_email, payment_id, product_id)
                        VALUES (:wid, :evt, :uid, :email, :pay, :prod)
                        ON CONFLICT (webhook_id) DO NOTHING
                        """,
                        {
                            "wid": webhook_id,
                            "evt": event_type,
                            "uid": resolved_uid,
                            "email": customer_email,
                            "pay": payment_id,
                            "prod": product_id,
                        },
                    )
                except Exception:
                    logger.exception("[dodo-webhook] idempotency record insert failed")
                await session.commit()
            logger.info("[dodo-webhook] updated plan=%s for uid=%s via Neon", new_plan, resolved_uid)
    except Exception:
        logger.exception("[dodo-webhook] failed to update user plan in Neon")

    return {"status": "ok", "uid": resolved_uid, "plan": new_plan, "event_type": event_type}
# CORS preflight for webhook path variants
@router.options("/api/payments/dodo/webhook")
@router.options("/api/payments/dodo/webhook/")
async def dodo_webhook_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, webhook-id, webhook-signature, webhook-timestamp",
    })
