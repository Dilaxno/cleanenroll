from __future__ import annotations

import os
import logging
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Body
from fastapi.responses import JSONResponse

# Rate limiter
try:
    from utils.limiter import limiter, forwarded_for_ip  # type: ignore
except Exception:  # pragma: no cover
    from utils.limiter import limiter, forwarded_for_ip  # type: ignore

# Firebase Admin (Auth only)
try:
    import firebase_admin  # type: ignore
    from firebase_admin import auth as admin_auth  # type: ignore
    from firebase_admin import credentials as admin_credentials  # type: ignore

    _FB_AVAILABLE = True
except Exception:  # pragma: no cover
    firebase_admin = None  # type: ignore
    admin_auth = None  # type: ignore
    admin_credentials = None  # type: ignore
    admin_firestore = None  # type: ignore

    _FB_AVAILABLE = False

# Fuzzy/semantic match (lightweight)
try:
    from rapidfuzz import fuzz  # type: ignore
except Exception:  # pragma: no cover
    fuzz = None  # type: ignore

logger = logging.getLogger("backend.admin")

router = APIRouter(prefix="/admin", tags=["admin"])


# --- Firebase bootstrap

def _ensure_firebase_initialized():
    # Initialize Firebase Admin only for Auth operations (claims/updates). Firestore is no longer used.
    if not _FB_AVAILABLE:
        raise HTTPException(status_code=500, detail="Firebase Admin SDK not available on server.")
    if not firebase_admin._apps:  # type: ignore
        try:
            cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.path.join(os.getcwd(), "cleanenroll-fd36a-firebase-adminsdk-fbsvc-7d79b92b3f.json")
            if cred_path and os.path.exists(cred_path):
                logger.info("[admin] Initializing Firebase Admin with service account at %s", cred_path)
                cred = admin_credentials.Certificate(cred_path)
            else:
                logger.info("[admin] Initializing Firebase Admin with Application Default Credentials")
                cred = admin_credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred)
            logger.info("[admin] Firebase Admin initialized")
        except Exception as e:  # pragma: no cover
            logger.exception("[admin] Firebase Admin initialization failed")
            raise HTTPException(status_code=500, detail=f"Failed to initialize Firebase Admin: {e}")


# --- Security helpers

def _require_admin(request: Request) -> Dict[str, Any]:
    """
    Authorize via either:
      - Header X-Admin-Secret matching BACKEND_ADMIN_SECRET (or ADMIN_SECRET)
      - Firebase ID token with custom claim { admin: true } or role in {admin, owner}
      - Fallback: email allowlist via ALLOW_ADMIN_EMAILS (comma-separated)
    Returns a dict describing auth context.
    """
    # 1) Shared secret header
    hdr = request.headers.get("x-admin-secret") or request.headers.get("x-cleanenroll-admin")
    env_secret = os.getenv("BACKEND_ADMIN_SECRET") or os.getenv("ADMIN_SECRET")
    if hdr and env_secret and hdr.strip() == env_secret.strip():
        return {"method": "secret", "uid": None}

    # 2) Firebase ID token
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    token = None
    if authz and authz.lower().startswith("bearer "):
        token = authz.split(" ", 1)[1].strip()

    if token and _FB_AVAILABLE and admin_auth is not None:
        try:
            decoded = admin_auth.verify_id_token(token)
            uid = decoded.get("uid")
            claims = decoded or {}
            if claims.get("admin") is True or (str(claims.get("role") or "").lower() in {"admin", "owner"}):
                return {"method": "claims", "uid": uid, "claims": claims}
            # Email allowlist fallback
            allowlist = os.getenv("ALLOW_ADMIN_EMAILS", "")
            allow = {e.strip().lower() for e in allowlist.split(",") if e.strip()}
            email = str(claims.get("email") or "").lower()
            if email and email in allow:
                return {"method": "allowlist", "uid": uid, "claims": claims}
        except Exception:  # pragma: no cover
            pass

    raise HTTPException(status_code=403, detail="Admin access denied")


# --- Models
from pydantic import BaseModel, Field

try:
    from db.database import async_session_maker  # type: ignore
except Exception:
    from ..db.database import async_session_maker  # type: ignore
try:
    from sqlalchemy import text as _text  # type: ignore
except Exception:
    _text = None  # type: ignore

class AdminUserUpdate(BaseModel):
    plan: Optional[str] = None
    billing: Optional[Dict[str, Any]] = None
    cancelAtPeriodEnd: Optional[bool] = None
    allowGoogleSignin: Optional[bool] = None
    formsCount: Optional[int] = Field(default=None, ge=0)
    emailVerified: Optional[bool] = None
    disabled: Optional[bool] = None
    # Arbitrary additional fields to merge into users doc
    extra: Optional[Dict[str, Any]] = None


# Ensure forward refs are resolved with Pydantic v2 when using postponed annotations
AdminUserUpdate.model_rebuild()


# --- Utilities

def _user_auth_info(uid: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {"uid": uid}
    if not (_FB_AVAILABLE and admin_auth is not None):
        return info
    try:
        u = admin_auth.get_user(uid)
        info.update({
            "email": getattr(u, "email", None),
            "displayName": getattr(u, "display_name", None),
            "photoURL": getattr(u, "photo_url", None),
            "emailVerified": bool(getattr(u, "email_verified", False)),
            "disabled": bool(getattr(u, "disabled", False)),
            "createdAt": getattr(getattr(u, "user_metadata", None), "creation_timestamp", None),
            "lastLoginAt": getattr(getattr(u, "user_metadata", None), "last_sign_in_timestamp", None),
            "providerIds": [p.provider_id for p in getattr(u, "provider_data", [])],
        })
    except Exception:
        pass
    return info


def _augment_with_auth(items: List[Dict[str, Any]]) -> None:
    # Sequentially augment; for large lists consider batching or skipping
    for it in items:
        uid = str(it.get("uid") or it.get("id") or "").strip()
        if not uid:
            continue
        auth_info = _user_auth_info(uid)
        # Don't override Firestore fields if already set
        for k, v in auth_info.items():
            if k not in it or it[k] in (None, ""):
                it[k] = v


def _score(query: str, user: Dict[str, Any]) -> int:
    hay = " ".join([
        str(user.get("email") or ""),
        str(user.get("displayName") or ""),
        str(user.get("plan") or ""),
        str(user.get("uid") or user.get("id") or ""),
    ]).lower()
    email_lower = str(user.get("email") or "").lower()
    q = (query or "").lower().strip()
    if not q:
        return 0
    # Boost results that have the email containing the prefix directly
    boost = 0
    if q in email_lower:
        boost += 30 if len(q) < 5 else 15
    if fuzz is None:
        # Simple containment preference
        return (85 + min(15, len(q)) + boost) if q in hay else boost
    try:
        base = int(max(
            fuzz.partial_ratio(q, hay),
            fuzz.token_set_ratio(q, hay),
            fuzz.WRatio(q, hay),
        ))
        return base + boost
    except Exception:
        return boost


# --- Endpoints

@router.get("/health")
@limiter.limit("10/minute")
async def admin_health(request: Request):  # pragma: no cover
    return {"status": "ok"}


@router.get("/users")
@limiter.limit("60/minute")
async def list_users(
    request: Request,
    q: Optional[str] = Query(default=None, description="Search by email/name/uid/plan (simple)"),
    plan: Optional[str] = Query(default=None, description="Filter by plan (free/pro/...)"),
    email_verified: Optional[bool] = Query(default=None, description="Filter by emailVerified (auth)", alias="emailVerified"),
    disabled: Optional[bool] = Query(default=None, description="Filter by disabled (auth)", alias="is_disabled"),
    limit: int = Query(default=50, ge=1, le=200),
):
    _ = _require_admin(request)
    try:
        where = ["1=1"]
        params: Dict[str, Any] = {}
        if plan:
            where.append("LOWER(plan) = :plan")
            params["plan"] = plan.lower().strip()
        if q:
            where.append("(uid = :q OR LOWER(email) LIKE :like OR LOWER(display_name) LIKE :like OR LOWER(plan) LIKE :like)")
            params["q"] = q.strip()
            params["like"] = f"%{q.lower().strip()}%"
        sql = (
            "SELECT uid, email, display_name, photo_url, plan, forms_count, signup_ip, signup_country, "
            "signup_geo_lat, signup_geo_lon, signup_user_agent, signup_at, created_at, updated_at "
            f"FROM users WHERE {' AND '.join(where)} ORDER BY created_at DESC NULLS LAST LIMIT :limit"
        )
        params["limit"] = int(limit)
        items: List[Dict[str, Any]] = []
        async with async_session_maker() as session:
            res = await session.execute(_text(sql), params)
            rows = res.fetchall()
        for r in rows:
            it = {
                "uid": r[0],
                "email": r[1],
                "displayName": r[2],
                "photoURL": r[3],
                "plan": (r[4] or "").lower() if r[4] else None,
                "formsCount": r[5],
                "signupIp": r[6],
                "signupCountry": r[7],
                "signupGeoLat": r[8],
                "signupGeoLon": r[9],
                "signupUserAgent": r[10],
                "signupAt": r[11],
                "createdAt": r[12],
                "updatedAt": r[13],
            }
            items.append(it)

        # Augment with Auth metadata to support emailVerified/disabled filter/search
        _augment_with_auth(items)
        if email_verified is not None:
            items = [it for it in items if bool(it.get("emailVerified")) == bool(email_verified)]
        if disabled is not None:
            items = [it for it in items if bool(it.get("disabled")) == bool(disabled)]

        # If q provided, apply simple scoring for ordering
        if q:
            for it in items:
                it["_score"] = _score(q, it)
            items.sort(key=lambda x: x.get("_score", 0), reverse=True)

        items = items[:limit]
        return {"items": items, "count": len(items)}
    except Exception as e:
        logger.exception("[admin] list_users error")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users/{uid}")
@limiter.limit("60/minute")
async def get_user(request: Request, uid: str):
    _ = _require_admin(request)
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                _text(
                    "SELECT uid, email, display_name, photo_url, plan, forms_count, signup_ip, signup_country, "
                    "signup_geo_lat, signup_geo_lon, signup_user_agent, signup_at, created_at, updated_at "
                    "FROM users WHERE uid = :uid"
                ),
                {"uid": uid},
            )
            row = res.first()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        data: Dict[str, Any] = {
            "uid": row[0],
            "email": row[1],
            "displayName": row[2],
            "photoURL": row[3],
            "plan": (row[4] or "").lower() if row[4] else None,
            "formsCount": row[5],
            "signupIp": row[6],
            "signupCountry": row[7],
            "signupGeoLat": row[8],
            "signupGeoLon": row[9],
            "signupUserAgent": row[10],
            "signupAt": row[11],
            "createdAt": row[12],
            "updatedAt": row[13],
        }
        auth_info = _user_auth_info(uid)
        for k, v in auth_info.items():
            if k not in data or data[k] in (None, ""):
                data[k] = v
        return data
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("[admin] get_user error")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/users/{uid}")
@limiter.limit("30/minute")
async def update_user(request: Request, uid: str, payload: AdminUserUpdate = Body(...)):
    _ = _require_admin(request)
    # Build Neon updates limited to existing columns
    set_parts: List[str] = []
    params: Dict[str, Any] = {"uid": uid}
    if payload.plan is not None:
        set_parts.append("plan = :plan")
        params["plan"] = str(payload.plan).lower().strip()
    if payload.formsCount is not None:
        set_parts.append("forms_count = :forms_count")
        params["forms_count"] = int(payload.formsCount)
    if set_parts:
        set_sql = ", ".join(set_parts + ["updated_at = NOW()"])
        try:
            async with async_session_maker() as session:
                await session.execute(_text(f"UPDATE users SET {set_sql} WHERE uid = :uid"), params)
                await session.commit()
        except Exception as e:
            logger.exception("[admin] update_user Neon update failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Auth updates
    auth_changes = {}
    if payload.emailVerified is not None:
        auth_changes["email_verified"] = bool(payload.emailVerified)
    if payload.disabled is not None:
        auth_changes["disabled"] = bool(payload.disabled)
    if auth_changes and _FB_AVAILABLE and admin_auth is not None:
        try:
            _ensure_firebase_initialized()
            admin_auth.update_user(uid, **auth_changes)
        except Exception as e:
            logger.warning("[admin] Failed to update Firebase Auth for %s: %s", uid, e)

    # Return a summary of what we changed (Neon subset)
    return {"status": "ok", "updated": {k: params[k] for k in params if k != "uid"}, "authUpdated": bool(auth_changes)}


@router.post("/users/{uid}/delete")
@limiter.limit("10/minute")
async def delete_user(request: Request, uid: str, hard: bool = Query(default=True)):
    _ = _require_admin(request)
    # 1) Delete or disable Auth record
    auth_status = None
    if _FB_AVAILABLE and admin_auth is not None:
        try:
            if hard:
                admin_auth.delete_user(uid)
                auth_status = "deleted"
            else:
                admin_auth.update_user(uid, disabled=True)
                auth_status = "disabled"
        except Exception as e:
            logger.warning("[admin] Auth delete/disable failed for %s: %s", uid, e)
    # 2) Neon: delete user row (cascades)
    try:
        async with async_session_maker() as session:
            await session.execute(_text("DELETE FROM users WHERE uid = :uid"), {"uid": uid})
            await session.commit()
    except Exception as e:
        logger.warning("[admin] Neon delete failed for %s: %s", uid, e)
        raise HTTPException(status_code=500, detail="Failed to delete user")

    return {"status": "ok", "auth": auth_status, "deleted": True}


@router.post("/users/{uid}/claims")
@limiter.limit("20/minute")
async def set_custom_claims(request: Request, uid: str, claims: Dict[str, Any] = Body(...)):
    _ = _require_admin(request)
    _ensure_firebase_initialized()
    if not (_FB_AVAILABLE and admin_auth is not None):
        raise HTTPException(status_code=500, detail="Firebase Auth unavailable")
    try:
        # Merge with existing claims
        existing = admin_auth.get_user(uid).custom_claims or {}
        merged = dict(existing)
        merged.update({k: v for k, v in claims.items() if k not in {"aud", "iss", "sub", "iat", "exp"}})
        admin_auth.set_custom_user_claims(uid, merged)
        return {"status": "ok", "claims": merged}
    except Exception as e:
        logger.exception("[admin] set_custom_claims failed")
        raise HTTPException(status_code=500, detail=str(e))
        
        
        # --- Migration: Firestore submissions -> backend file store used by /responses
RESPONSES_BASE_DIR = os.path.join(os.getcwd(), "data", "responses")
os.makedirs(RESPONSES_BASE_DIR, exist_ok=True)


def _to_iso(ts) -> str:
    try:
        if isinstance(ts, datetime):
            dt = ts
        else:
            # Fallback: Firestore Timestamp can already be a datetime with tz
            dt = ts  # type: ignore
        if dt is None:
            return datetime.now(timezone.utc).isoformat()
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        try:
            # Last resort
            return datetime.now(timezone.utc).isoformat()
        except Exception:
            return ""


def _responses_dir(form_id: str) -> str:
    d = os.path.join(RESPONSES_BASE_DIR, form_id)
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return d


def _load_existing_response_ids(form_id: str) -> set:
    ids = set()
    try:
        d = _responses_dir(form_id)
        if not os.path.exists(d):
            return ids
        for name in os.listdir(d):
            if not name.endswith('.json'):
                continue
            try:
                with open(os.path.join(d, name), 'r', encoding='utf-8') as f:
                    rec = json.load(f)
                    rid = str((rec or {}).get('responseId') or '').strip()
                    if rid:
                        ids.add(rid)
            except Exception:
                continue
    except Exception:
        pass
    return ids


@router.post("/migrate/firestore-submissions")
@limiter.limit("5/minute")
async def migrate_firestore_submissions(
    request: Request,
    formId: Optional[str] = Query(default=None, description="Limit migration to a specific formId"),
    limit: int = Query(default=0, ge=0, le=500000, description="Max docs to process (0 = no explicit limit)"),
    dryRun: bool = Query(default=False, description="If true, do not write files; only count operations"),
):
    # Removed: Firestore utilities are no longer available
    raise HTTPException(status_code=404, detail="Endpoint removed")


# Firestore Explorer Admin APIs removed (intentionally not implemented)
