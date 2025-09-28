from __future__ import annotations

import os
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Body
from fastapi.responses import JSONResponse

# Rate limiter
try:
    from ..utils.limiter import limiter, forwarded_for_ip  # type: ignore
except Exception:  # pragma: no cover
    from utils.limiter import limiter, forwarded_for_ip  # type: ignore

# Firebase Admin (Auth + Firestore)
try:
    import firebase_admin  # type: ignore
    from firebase_admin import auth as admin_auth  # type: ignore
    from firebase_admin import credentials as admin_credentials  # type: ignore
    from firebase_admin import firestore as admin_firestore  # type: ignore
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
    if not _FB_AVAILABLE:
        raise HTTPException(status_code=500, detail="Firebase Admin SDK not available on server.")
    if not firebase_admin._apps:  # type: ignore
        # Initialize with GOOGLE_APPLICATION_CREDENTIALS or application default
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
    q: Optional[str] = Query(default=None, description="Semantic search query (email/name/uid/plan)"),
    plan: Optional[str] = Query(default=None, description="Filter by plan (free/pro/...)"),
    email_verified: Optional[bool] = Query(default=None, description="Filter by emailVerified (auth or users doc)"),
    disabled: Optional[bool] = Query(default=None, description="Filter by disabled (auth)", alias="is_disabled"),
    limit: int = Query(default=50, ge=1, le=200),
):
    _ = _require_admin(request)
    _ensure_firebase_initialized()
    if admin_firestore is None:
        raise HTTPException(status_code=500, detail="Firestore client unavailable")

    fs = admin_firestore.client()
    col = fs.collection("users")

    try:
        items_map: Dict[str, Dict[str, Any]] = {}
        q_norm = (q or "").strip()
        plan_norm = (plan or "").strip().lower() or None

        # 1) Exact matches first for best precision
        if q_norm:
            # by doc id (uid)
            try:
                d = col.document(q_norm).get()
                if d.exists:
                    data = d.to_dict() or {}
                    data["id"] = d.id
                    data.setdefault("uid", d.id)
                    if isinstance(data.get("plan"), str):
                        data["plan"] = data["plan"].lower()
                    data["_score"] = 1000  # strong boost for exact id
                    items_map[data["uid"]] = data
            except Exception:
                pass
            # by email equality
            try:
                eq_docs = list(col.where("email", "==", q_norm.lower()).limit(5).stream())
                for d in eq_docs:
                    data = d.to_dict() or {}
                    data["id"] = d.id
                    data.setdefault("uid", d.id)
                    if isinstance(data.get("plan"), str):
                        data["plan"] = data["plan"].lower()
                    data["_score"] = max(900, int(data.get("_score", 0)))
                    items_map[data["uid"]] = data
            except Exception:
                pass
            # by email prefix (best-effort; assumes stored emails are lowercase)
            try:
                ql = q_norm.lower()
                if ql:
                    prefix_docs = list(
                        col.where("email", ">=", ql).where("email", "<", ql + "\uf8ff").limit(50).stream()
                    )
                    for d in prefix_docs:
                        data = d.to_dict() or {}
                        data["id"] = d.id
                        data.setdefault("uid", d.id)
                        if isinstance(data.get("plan"), str):
                            data["plan"] = data["plan"].lower()
                        data["_score"] = max(800, int(data.get("_score", 0)))
                        items_map[data["uid"]] = data
            except Exception:
                pass

        # 2) Broader page to fuzzy-match and/or filter by plan
        query_ref = col
        # Try to use Firestore plan equality if provided (best-effort)
        try:
            if plan_norm:
                query_ref = query_ref.where("plan", "==", plan_norm)
        except Exception:
            # continue without Firestore plan filter (we'll filter in-memory)
            query_ref = col
        # Default sort by createdAt desc
        try:
            query_ref = query_ref.order_by("createdAt", direction=admin_firestore.Query.DESCENDING)  # type: ignore
        except Exception:
            pass
        # Fetch a larger slice for good fuzzy coverage when searching
        fetch_count = 800 if q_norm else max(limit, 100)
        docs = list(query_ref.limit(fetch_count).stream())

        for d in docs:
            data = d.to_dict() or {}
            data["id"] = d.id
            data.setdefault("uid", d.id)
            if isinstance(data.get("plan"), str):
                data["plan"] = data["plan"].lower()
            uid = data["uid"]
            if uid not in items_map:
                items_map[uid] = data

        # 3) Build list and pre-augment with Auth so email is available for scoring
        items = list(items_map.values())

        # In-memory plan filter for robustness (case-insensitive)
        if plan_norm:
            items = [it for it in items if str(it.get("plan") or "").lower() == plan_norm]

        # Augment with Auth BEFORE scoring so semantic search matches auth email/metadata
        _augment_with_auth(items)

        # Apply fuzzy search + boost
        if q_norm:
            for it in items:
                base = int(it.get("_score", 0))
                sc = _score(q_norm, it)
                it["_score"] = base + sc
            items.sort(key=lambda x: x.get("_score", 0), reverse=True)
            thr = 15 if len(q_norm) <= 3 else (25 if len(q_norm) <= 5 else 40)
            items = [it for it in items if it.get("_score", 0) >= thr]

        # 5) Apply post-auth filters
        if email_verified is not None:
            items = [it for it in items if bool(it.get("emailVerified")) == bool(email_verified)]
        if disabled is not None:
            items = [it for it in items if bool(it.get("disabled")) == bool(disabled)]

        # Limit final results
        items = items[:limit]

        return {"items": items, "count": len(items)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("[admin] list_users error")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users/{uid}")
@limiter.limit("60/minute")
async def get_user(request: Request, uid: str):
    _ = _require_admin(request)
    _ensure_firebase_initialized()
    if admin_firestore is None:
        raise HTTPException(status_code=500, detail="Firestore client unavailable")
    fs = admin_firestore.client()
    d = fs.collection("users").document(uid).get()
    data = d.to_dict() or {}
    data.setdefault("uid", uid)
    data.setdefault("id", uid)
    auth_info = _user_auth_info(uid)
    # Merge auth info, don't override Firestore non-null
    for k, v in auth_info.items():
        if k not in data or data[k] in (None, ""):
            data[k] = v
    return data


@router.patch("/users/{uid}")
@limiter.limit("30/minute")
async def update_user(request: Request, uid: str, payload: AdminUserUpdate = Body(...)):
    _ = _require_admin(request)
    _ensure_firebase_initialized()
    if admin_firestore is None:
        raise HTTPException(status_code=500, detail="Firestore client unavailable")

    fs = admin_firestore.client()
    updates: Dict[str, Any] = {}

    if payload.plan is not None:
        updates["plan"] = str(payload.plan).lower().strip()
        updates["planUpdatedAt"] = admin_firestore.SERVER_TIMESTAMP
        updates["planSource"] = "admin"
    if payload.billing is not None:
        updates["billing"] = payload.billing
    if payload.cancelAtPeriodEnd is not None:
        updates["cancelAtPeriodEnd"] = bool(payload.cancelAtPeriodEnd)
    if payload.allowGoogleSignin is not None:
        updates["allowGoogleSignin"] = bool(payload.allowGoogleSignin)
    if payload.formsCount is not None:
        updates["formsCount"] = int(payload.formsCount)
    if payload.extra:
        for k, v in (payload.extra or {}).items():
            updates[k] = v
    if updates:
        updates["updatedAt"] = admin_firestore.SERVER_TIMESTAMP
        fs.collection("users").document(uid).set(updates, merge=True)

    # Auth updates
    auth_changes = {}
    if payload.emailVerified is not None:
        auth_changes["email_verified"] = bool(payload.emailVerified)
    if payload.disabled is not None:
        auth_changes["disabled"] = bool(payload.disabled)
    if auth_changes and _FB_AVAILABLE and admin_auth is not None:
        try:
            admin_auth.update_user(uid, **auth_changes)
        except Exception as e:
            logger.warning("[admin] Failed to update Firebase Auth for %s: %s", uid, e)

    return {"status": "ok", "updated": updates, "authUpdated": bool(auth_changes)}


def _delete_collection(fs, coll_ref, batch_size=250):
    docs = list(coll_ref.limit(batch_size).stream())
    deleted = 0
    for d in docs:
        d.reference.delete()
        deleted += 1
    if deleted >= batch_size:
        return deleted + _delete_collection(fs, coll_ref, batch_size)
    return deleted


@router.post("/users/{uid}/delete")
@limiter.limit("10/minute")
async def delete_user(request: Request, uid: str, hard: bool = Query(default=True)):
    _ = _require_admin(request)
    _ensure_firebase_initialized()
    if admin_firestore is None:
        raise HTTPException(status_code=500, detail="Firestore client unavailable")

    fs = admin_firestore.client()

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

    # 2) Firestore: delete user doc and related docs
    total_deleted = 0
    try:
        # users/{uid}
        fs.collection("users").document(uid).delete()
        # notifiedUsers/{uid}
        fs.collection("notifiedUsers").document(uid).delete()
        # notifications/{uid}/items/*
        total_deleted += _delete_collection(fs, fs.collection("notifications").document(uid).collection("items"))
        # users/{uid}/devices/*
        total_deleted += _delete_collection(fs, fs.collection("users").document(uid).collection("devices"))
        # forms owned by user + subcollections
        forms = list(fs.collection("forms").where("userId", "==", uid).stream())
        for f in forms:
            fid = f.id
            # analytics
            total_deleted += _delete_collection(fs, fs.collection("forms").document(fid).collection("analytics"))
            # abandons
            total_deleted += _delete_collection(fs, fs.collection("form_abandons").document(fid).collection("entries"))
            # form doc
            fs.collection("forms").document(fid).delete()
            total_deleted += 1
    except Exception as e:
        logger.warning("[admin] Firestore cleanup encountered errors for %s: %s", uid, e)

    return {"status": "ok", "auth": auth_status, "deletedCount": total_deleted}


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
