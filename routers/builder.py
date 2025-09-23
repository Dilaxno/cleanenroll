from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Literal, Any
import logging
from datetime import datetime
import os
import json
import uuid
import urllib.parse
import urllib.request

# Email sender (Resend preferred)
try:
    from ..utils.email import send_email_html  # type: ignore
except Exception:
    from utils.email import send_email_html  # type: ignore

# Email validation
from email_validator import validate_email as _validate_email, EmailNotValidError as _EmailNotValidError

# GeoIP
import os
from typing import Tuple
from pathlib import Path
import tarfile

try:
    import geoip2.database  # type: ignore
    _GEOIP_IMPORTED = True
except Exception:
    geoip2 = None  # type: ignore
    _GEOIP_IMPORTED = False

# Logger
logger = logging.getLogger("backend.builder")


def _resolve_geoip_db_path() -> str:
    r"""Resolve a usable .mmdb path.
    Priority:
      1) GEOIP_DB_PATH env var if it points to an existing .mmdb
      2) GEOIP_DB_PATH env var as a .tar.gz archive -> extract first .mmdb found
      3) Default archive path D:\CleanEnroll\GeoLite2-City_20250919.tar.gz -> extract
      4) Fallback to data/GeoLite2-Country.mmdb
    """
    env_path = os.getenv("GEOIP_DB_PATH")
    candidates = [env_path] if env_path else []
    candidates.append("D:\\CleanEnroll\\GeoLite2-City_20250919.tar.gz")

    # Helper to extract .mmdb from archive
    def extract_from_archive(archive_path: Path) -> str:
        try:
            extract_root = Path(os.getcwd()) / "data" / "geoip"
            extract_root.mkdir(parents=True, exist_ok=True)
            # Extract only .mmdb entries safely
            with tarfile.open(str(archive_path), "r:gz") as tar:
                # Find first .mmdb member
                mmdb_member = next((m for m in tar.getmembers() if m.name.lower().endswith(".mmdb")), None)
                if not mmdb_member:
                    return ""
                # Normalize target filename
                target = extract_root / Path(mmdb_member.name).name
                if not target.exists():
                    # Extract to temp dir then move specific file
                    tar.extract(mmdb_member, path=str(extract_root))
                    extracted_path = extract_root / mmdb_member.name
                    # If extracted nested, move into extract_root
                    if extracted_path.exists() and extracted_path.is_file():
                        extracted_path.rename(target)
                    elif extracted_path.exists() and extracted_path.is_dir():
                        for p in extracted_path.rglob("*.mmdb"):
                            p.rename(extract_root / p.name)
                            target = extract_root / p.name
                            break
                return str(target)
        except Exception:
            return ""

    # Try candidates
    for c in candidates:
        if not c:
            continue
        p = Path(c)
        # .mmdb direct
        if p.suffix.lower() == ".mmdb" and p.exists():
            return str(p)
        # .tar.gz
        if str(p).lower().endswith(".tar.gz") and p.exists():
            resolved = extract_from_archive(p)
            if resolved and Path(resolved).exists():
                return resolved

    # Fallback
    return str(Path(os.getcwd()) / "data" / "GeoLite2-Country.mmdb")


GEOIP_DB_PATH = _resolve_geoip_db_path()
_GEOIP_AVAILABLE = _GEOIP_IMPORTED and Path(GEOIP_DB_PATH).exists()

router = APIRouter(prefix="/api/builder", tags=["builder"]) 

# Use the shared limiter instance configured in utils.limiter
try:
    from ..utils.limiter import limiter  # type: ignore
except Exception:
    from utils.limiter import limiter  # type: ignore

# Storage
BACKING_DIR = os.path.join(os.getcwd(), "data", "forms")
os.makedirs(BACKING_DIR, exist_ok=True)

# Responses storage (separate from form schemas)
RESPONSES_BASE_DIR = os.path.join(os.getcwd(), "data", "responses")
os.makedirs(RESPONSES_BASE_DIR, exist_ok=True)


def _form_path(form_id: str) -> str:
    return os.path.join(BACKING_DIR, f"{form_id}.json")


def _responses_dir(form_id: str) -> str:
    """Directory where responses for a given form are stored."""
    d = os.path.join(RESPONSES_BASE_DIR, form_id)
    os.makedirs(d, exist_ok=True)
    return d


def _new_response_path(form_id: str, submitted_at_iso: str, response_id: str) -> str:
    """Generate a filesystem-safe path for a new response file."""
    safe_ts = str(submitted_at_iso).replace(":", "-")
    return os.path.join(_responses_dir(form_id), f"{safe_ts}_{response_id}.json")


def _write_json(path: str, data: Dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _read_json(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Models aligned with the front-end builder
class SubmitButton(BaseModel):
    label: str = "Submit"
    color: str = "#3b82f6"
    textColor: str = "#ffffff"


class Branding(BaseModel):
    logo: Optional[str] = None  # data URL or external URL
    logoPosition: Literal["top", "bottom"] = "top"
    logoSize: Literal["small", "medium", "large"] = "medium"
    # New branding visuals support
    headerImage: Optional[str] = None
    visuals: Optional[List[Dict[str, Any]]] = []


class ThemeSchema(BaseModel):
    primaryColor: str = "#4f46e5"
    backgroundColor: str = "#ffffff"
    pageBackgroundColor: str = "#ffffff"
    textColor: str = "#111827"
    titleColor: str = "#000000"
    inputBgColor: str = "#ffffff"
    inputTextColor: str = "#111827"
    inputBorderColor: str = "#d1d5db"
    inputBorderRadius: int = 8
    # Persist builder border customization
    inputBorderWidth: int = 1
    inputBorderStyle: Literal["none", "solid", "dashed", "dotted", "double", "groove", "ridge", "inset", "outset"] = "solid"
    inputBorderSide: Literal["all", "top", "right", "bottom", "left"] = "all"
    # Thank-you screen colors
    thankYouBgColor: str = "#ecfdf5"
    thankYouTextColor: str = "#065f46"


class RedirectConfig(BaseModel):
    enabled: bool = False
    url: str = ""


class FieldSchema(BaseModel):
    id: str
    label: str
    type: Literal[
        "text",
        "textarea",
        "number",
        "checkbox",
        "dropdown",
        "multiple",
        "date",
        "location",
        "address",
        "url",
        "file",
    ]
    required: bool = False
    placeholder: Optional[str] = None
    options: Optional[List[str]] = None
    step: Optional[int] = Field(default=1, ge=1)
    maxLength: Optional[int] = Field(default=None, gt=0)
    accept: Optional[str] = None
    multiple: Optional[bool] = None

    @validator("options", always=True)
    def normalize_options(cls, v, values):
        # Ensure options for dropdown/multiple when present
        ftype = values.get("type")
        if ftype in ("dropdown", "multiple"):
            if not v or len([o for o in (v or []) if str(o).strip()]) == 0:
                # allow empty here; validation performed at form level to provide better error message
                return []
        return v


class FormConfig(BaseModel):
    id: Optional[str] = None
    userId: Optional[str] = None
    title: str = "Untitled Form"
    subtitle: str = ""
    thankYouMessage: str = "Thank you for your submission! We'll get back to you soon."
    redirect: RedirectConfig = RedirectConfig()
    emailValidationEnabled: bool = False
    recaptchaEnabled: bool = False
    gdprComplianceEnabled: bool = False
    passwordProtectionEnabled: bool = False
    passwordHash: Optional[str] = None
    preventDuplicateByUID: bool = False
    isPublished: bool = False
    submitButton: SubmitButton = SubmitButton()
    formType: Literal["simple", "multi-step"] = "simple"
    theme: ThemeSchema = ThemeSchema()
    branding: Branding = Branding()
    fields: List[FieldSchema] = []
    restrictedCountries: Optional[List[str]] = []  # ISO alpha-2 codes (e.g., ["US","FR"]) uppercased
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None


# -----------------------------
# Helpers
# -----------------------------

EXTENDED_ALLOWED_TYPES = {
    "text",
    "textarea",
    "number",
    "checkbox",
    "dropdown",
    "multiple",
    "date",
    "location",
    "address",
    "url",
    "file",
}


def _validate_form(cfg: FormConfig):
    # Field type guard and additional requirements
    for f in cfg.fields:
        if f.type not in EXTENDED_ALLOWED_TYPES:
            raise HTTPException(status_code=400, detail=f"Unsupported field type: {f.type}")
        if f.type in ("dropdown", "multiple"):
            if not f.options or len([o for o in f.options if str(o).strip()]) == 0:
                raise HTTPException(status_code=400, detail=f"Field '{f.label}' requires at least one option")
        if f.type in ("text", "textarea") and f.maxLength is not None and f.maxLength <= 0:
            raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid maxLength")

    

def _create_id() -> str:
    return uuid.uuid4().hex


RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET_KEY") or os.getenv("RECAPTCHA_SECRET") or ""
PIXABAY_API_KEY = os.getenv("PIXABAY_API_KEY") or ""

def _verify_recaptcha(token: str, remoteip: str = "") -> bool:
    if not RECAPTCHA_SECRET:
        return False
    try:
        payload = urllib.parse.urlencode({
            "secret": RECAPTCHA_SECRET,
            "response": token,
            "remoteip": remoteip or ""
        }).encode()
        with urllib.request.urlopen("https://www.google.com/recaptcha/api/siteverify", data=payload, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return bool(data.get("success"))
    except Exception:
        return False

# -----------------------------
# Geo helpers
# -----------------------------

def _normalize_country_list(codes: Optional[List[str]]) -> List[str]:
    if not codes:
        return []
    return [str(c).strip().upper() for c in codes if str(c).strip()]


def _client_ip(request: Request) -> str:
    # Prefer X-Forwarded-For if present (proxy/CDN)
    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if xff:
        # Take first IP
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    return request.client.host if request.client else ""


def _country_from_ip(ip: str) -> Tuple[bool, Optional[str]]:
    if not _GEOIP_AVAILABLE:
        return False, None
    if not ip:
        return False, None
    if not os.path.exists(GEOIP_DB_PATH):
        return False, None
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:  # type: ignore
            resp = reader.country(ip)
            code = (resp.country.iso_code or "").upper() if resp and resp.country else None
            return True, code
    except Exception:
        return False, None


# -----------------------------
# Routes
# -----------------------------

@router.get("/forms")
async def list_forms(userId: Optional[str] = Query(default=None, description="Filter by userId")):
    logger.debug("list_forms called userId=%s", userId)
    items: List[Dict] = []
    for name in os.listdir(BACKING_DIR):
        if not name.endswith(".json"):
            continue
        try:
            data = _read_json(os.path.join(BACKING_DIR, name))
            if userId and data.get("userId") != userId:
                continue
            items.append(data)
        except Exception:
            # Skip invalid files
            continue
    # Sort by createdAt desc if available
    def _key(d):
        ts = d.get("createdAt") or ""
        return ts
    items.sort(key=_key, reverse=True)
    return {"count": len(items), "forms": items}


@router.post("/forms")
async def create_form(cfg: FormConfig):
    _validate_form(cfg)
    now = datetime.utcnow().isoformat()
    form_id = _create_id()
    data = cfg.dict()
    # Preserve provided step values; default missing/invalid to 1
    for f in data.get("fields") or []:
        try:
            step_val = int(f.get("step") or 1)
            f["step"] = max(1, step_val)
        except Exception:
            f["step"] = 1
    # Normalize restrictedCountries to upper-case ISO codes
    data["restrictedCountries"] = _normalize_country_list(data.get("restrictedCountries") or [])
    data["id"] = form_id
    data["createdAt"] = now
    data["updatedAt"] = now
    data["isPublished"] = bool(data.get("isPublished", False))
    _write_json(_form_path(form_id), data)

    embed_url = f"/embed/{form_id}"
    iframe_snippet = f'<iframe src="{embed_url}" width="100%" height="600" frameborder="0"></iframe>'
    logger.info("form created id=%s fields=%s published=%s", form_id, len(data.get("fields") or []), bool(data.get("isPublished", False)))
    return {"id": form_id, "embedUrl": embed_url, "iframeSnippet": iframe_snippet}


@router.get("/forms/{form_id}")
async def get_form(form_id: str):
    logger.debug("get_form id=%s", form_id)
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    return _read_json(path)


@router.put("/forms/{form_id}")
async def update_form(form_id: str, cfg: FormConfig):
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")

    _validate_form(cfg)
    data = cfg.dict()
    # Preserve provided step values; default missing/invalid to 1
    for f in data.get("fields") or []:
        try:
            step_val = int(f.get("step") or 1)
            f["step"] = max(1, step_val)
        except Exception:
            f["step"] = 1
    # Normalize restrictedCountries to upper-case ISO codes
    data["restrictedCountries"] = _normalize_country_list(data.get("restrictedCountries") or [])
    data["id"] = form_id
    prev = _read_json(path)
    # Preserve published state if not explicitly provided
    existing_published = prev.get("isPublished", False)
    incoming_published = data.get("isPublished")
    data["isPublished"] = existing_published if incoming_published is None else bool(incoming_published)
    data["createdAt"] = prev.get("createdAt")  # preserve original
    data["updatedAt"] = datetime.utcnow().isoformat()

    _write_json(path, data)

    embed_url = f"/embed/{form_id}"
    iframe_snippet = f'<iframe src="{embed_url}" width="100%" height="600" frameborder="0"></iframe>'
    logger.info("form updated id=%s fields=%s published=%s", form_id, len(data.get("fields") or []), bool(data.get("isPublished", False)))
    return {"id": form_id, "embedUrl": embed_url, "iframeSnippet": iframe_snippet}


@router.delete("/forms/{form_id}")
async def delete_form(form_id: str):
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    try:
        os.remove(path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {e}")
    logger.info("form deleted id=%s", form_id)
    return {"success": True}


@router.get("/forms/{form_id}/embed")
async def get_embed_snippet(form_id: str):
    logger.debug("get_embed_snippet id=%s", form_id)
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    embed_url = f"/embed/{form_id}"
    iframe_snippet = f'<iframe src="{embed_url}" width="100%" height="600" frameborder="0"></iframe>'
    return {"id": form_id, "embedUrl": embed_url, "iframeSnippet": iframe_snippet}


@router.put("/forms/{form_id}/publish")
async def set_publish(form_id: str, payload: Dict = None):
    logger.debug("set_publish id=%s payload_keys=%s", form_id, list((payload or {}).keys()))
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    data = _read_json(path)
    desired = True
    if isinstance(payload, dict) and "isPublished" in payload:
        desired = bool(payload.get("isPublished"))
    data["isPublished"] = desired
    data["updatedAt"] = datetime.utcnow().isoformat()
    _write_json(path, data)
    logger.info("form publish updated id=%s isPublished=%s", form_id, desired)
    return {"success": True, "isPublished": desired}

@router.get("/forms/{form_id}/status")
async def get_status(form_id: str):
    logger.debug("get_status id=%s", form_id)
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    data = _read_json(path)
    return {"id": form_id, "isPublished": bool(data.get("isPublished", False))}

@router.get("/forms/{form_id}/geo-check")
async def geo_check(form_id: str, request: Request):
    """
    Check if the request IP is allowed to submit based on the form's restrictedCountries list.
    Returns {allowed: True, country: ISO} or raises 403 if blocked.
    """
    # Load form config
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    form_data = _read_json(path)

    restricted = _normalize_country_list(form_data.get("restrictedCountries") or [])
    if not restricted:
        logger.debug("geo_check id=%s unrestricted", form_id)
        return {"allowed": True, "country": None}

    ip = _client_ip(request)
    _, country = _country_from_ip(ip)

    # If we cannot determine country (no DB or IP), allow by default
    if not country:
        logger.debug("geo_check id=%s ip=%s country undetermined (allow)", form_id, ip)
        return {"allowed": True, "country": None}

    if country in restricted:
        # Block with required message
        logger.info("geo_check blocked id=%s ip=%s country=%s", form_id, ip, country)
        raise HTTPException(status_code=403, detail="Your IP location is restricted from submitting the form, We're sorry about that")

    logger.debug("geo_check allowed id=%s ip=%s country=%s", form_id, ip, country)
    return {"allowed": True, "country": country}


@router.get("/pixabay/search")
async def pixabay_search(
    q: str = Query("", description="Search query"),
    transparent: bool = Query(False, description="Prefer transparent PNG illustrations"),
    per_page: int = Query(24, ge=1, le=200),
    order: str = Query("popular", regex="^(popular|latest)$"),
    orientation: str = Query("horizontal", regex="^(all|horizontal|vertical)$"),
):
    """Proxy Pixabay search to avoid exposing API key to the client.
    Returns subset of fields for each hit.
    """
    if not PIXABAY_API_KEY:
        raise HTTPException(status_code=500, detail="Pixabay API not configured on server")
    try:
        query = (q or "").strip()
        if not query:
            query = "background" if transparent else "form"
        image_type = "illustration" if transparent else "photo"
        params = urllib.parse.urlencode({
            "key": PIXABAY_API_KEY,
            "q": query,
            "image_type": image_type,
            "safesearch": "true",
            "per_page": str(int(per_page)),
            "orientation": orientation,
            "order": order,
        })
        url = f"https://pixabay.com/api/?{params}"
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = resp.read().decode("utf-8")
        data = json.loads(body)
        hits = data.get("hits") or []
        # If transparent requested, heuristically keep PNGs
        if transparent:
            def is_png(u: str) -> bool:
                try:
                    return str(u or "").lower().endswith(".png")
                except Exception:
                    return False
            hits = [h for h in hits if is_png(h.get("largeImageURL") or h.get("webformatURL") or "")]
        # Map to subset
        out = []
        for h in hits:
            out.append({
                "id": h.get("id"),
                "tags": h.get("tags"),
                "previewURL": h.get("previewURL"),
                "webformatURL": h.get("webformatURL"),
                "largeImageURL": h.get("largeImageURL"),
                "pageURL": h.get("pageURL"),
                "user": h.get("user"),
                "userImageURL": h.get("userImageURL"),
                "type": h.get("type"),
            })
        return {"total": data.get("total", 0), "totalHits": data.get("totalHits", 0), "hits": out}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("pixabay_search error")
        raise HTTPException(status_code=500, detail=f"Pixabay search failed: {e}")

@router.post("/recaptcha/verify")
async def recaptcha_verify(request: Request, payload: Dict = None):
    """Verify a reCAPTCHA token with Google. Returns {"success": True} if valid."""
    token = None
    if isinstance(payload, dict):
        token = payload.get("token") or payload.get("recaptchaToken") or payload.get("g-recaptcha-response")
    if not token:
        raise HTTPException(status_code=400, detail="Missing reCAPTCHA token")
    if not RECAPTCHA_SECRET:
        raise HTTPException(status_code=500, detail="reCAPTCHA not configured on server")
    client_ip = _client_ip(request)
    ok = _verify_recaptcha(token, client_ip)
    if not ok:
        raise HTTPException(status_code=400, detail="reCAPTCHA verification failed")
    logger.info("recaptcha verified success ip=%s", client_ip)
    return {"success": True}

@router.post("/notify-submission")
async def notify_submission(payload: Dict = None):
    """Send a submission notification email using Resend (or SMTP fallback).
    Expected payload: { to: str, subject?: str, html?: str, formTitle?: str, summary?: str }
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")
    to = (payload.get("to") or "").strip()
    if not to:
        raise HTTPException(status_code=400, detail="Missing 'to' email")
    subject = (payload.get("subject") or f"New form submission").strip()
    html = payload.get("html")
    if not html:
        form_title = (payload.get("formTitle") or "").strip() or "Form"
        summary = (payload.get("summary") or "A new submission was received.").strip()
        html = f"""
        <div style='font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;'>
          <h2 style='margin:0 0 10px'>New submission: {form_title}</h2>
          <p style='margin:0 0 12px;color:#374151'>{summary}</p>
          <p style='margin:12px 0 0;color:#6b7280;font-size:12px'>This is an automated notification.</p>
        </div>
        """
    try:
        send_email_html(to, subject, html)
    except Exception as e:
        logger.exception("notify_submission send failed to=%s", to)
        raise HTTPException(status_code=500, detail=f"Failed to send: {e}")
    return {"success": True}

@router.post("/forms/{form_id}/submit")
@limiter.limit("5/minute")
async def submit_form(form_id: str, request: Request, payload: Dict = None):
    """Simple submission endpoint that enforces country restrictions.
    On success returns {success: True, message, redirectUrl?}.
    """
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")

    form_data = _read_json(path)

    # Password protection enforcement
    try:
        if bool(form_data.get("passwordProtectionEnabled")) and form_data.get("passwordHash"):
            supplied = None
            if isinstance(payload, dict):
                try:
                    supplied = (payload.get("_password") or payload.get("password") or "").strip()
                except Exception:
                    supplied = None
            if not supplied:
                raise HTTPException(status_code=401, detail="Password required to submit the form")
            import hashlib
            h = hashlib.sha256(supplied.encode("utf-8")).hexdigest()
            if h != str(form_data.get("passwordHash")):
                raise HTTPException(status_code=403, detail="Invalid password")
    except HTTPException:
        raise
    except Exception:
        # Do not leak details
        raise HTTPException(status_code=400, detail="Password verification failed")

    # Geo restriction enforcement
    restricted = _normalize_country_list(form_data.get("restrictedCountries") or [])
    if restricted:
        ip = _client_ip(request)
        _, country = _country_from_ip(ip)
        if country and country in restricted:
            raise HTTPException(status_code=403, detail="Your IP location is restricted from submitting the form, We're sorry about that")

    # reCAPTCHA verification when enabled
    if form_data.get("recaptchaEnabled"):
        if not isinstance(payload, dict):
            payload = payload or {}
        token = (
            (payload or {}).get("recaptchaToken")
            or (payload or {}).get("g-recaptcha-response")
            or (payload or {}).get("recaptcha")
        )
        if not token:
            raise HTTPException(status_code=400, detail="Missing reCAPTCHA token")
        client_ip = _client_ip(request)
        ok = _verify_recaptcha(token, client_ip)
        if not ok:
            raise HTTPException(status_code=400, detail="reCAPTCHA verification failed")
        logger.debug("submit_form recaptcha ok id=%s ip=%s", form_id, client_ip)

    # Email validation (format + MX) when enabled
    if form_data.get("emailValidationEnabled"):
        if not isinstance(payload, dict):
            payload = payload or {}
        fields_def = form_data.get("fields") or []
        emails_to_check = []
        for f in fields_def:
            try:
                label = str((f.get("label") or ""))
                ftype = f.get("type")
            except Exception:
                continue
            if ftype in ("text", "textarea") and "email" in label.lower():
                val = payload.get(f.get("id")) or payload.get(label)
                if val:
                    if isinstance(val, list):
                        for v in val:
                            emails_to_check.append((label, str(v)))
                    else:
                        emails_to_check.append((label, str(val)))
        for lab, addr in emails_to_check:
            try:
                _validate_email(addr, check_deliverability=True)
            except _EmailNotValidError as e:
                raise HTTPException(status_code=400, detail=f"Invalid email for field '{lab}': {str(e)}")

    # Success payload mirrors configured behavior
    # Build response payload for client
    resp: Dict[str, Optional[str] | bool] = {
        "success": True,
        "message": form_data.get("thankYouMessage"),
    }
    redir = form_data.get("redirect") or {}
    if redir.get("enabled") and redir.get("url"):
        resp["redirectUrl"] = redir.get("url")

    # Persist submission (store answers separately from form schema)
    try:
        submitted_at = datetime.utcnow().isoformat()
        response_id = uuid.uuid4().hex
        # Only persist answers for known fields, keyed by field id
        answers: Dict[str, object] = {}
        fields_def = form_data.get("fields") or []
        payload = payload or {}
        for f in fields_def:
            try:
                fid = str(f.get("id"))
                label = str(f.get("label") or "")
            except Exception:
                continue
            val = payload.get(fid)
            if val is None and label:
                val = payload.get(label)
            if val is not None:
                answers[fid] = val
        record = {
            "responseId": response_id,
            "formId": form_id,
            "submittedAt": submitted_at,
            "answers": answers,
        }
        _write_json(_new_response_path(form_id, submitted_at, response_id), record)
        # Optionally return responseId to the client
        resp["responseId"] = response_id  # type: ignore
    except Exception:
        # Swallow persistence errors to not break client submission flow
        logger.exception("submit_form persistence error id=%s", form_id)

    logger.info("form submitted id=%s response_id=%s", form_id, resp.get("responseId"))
    return resp

@router.get("/forms/{form_id}/responses")
async def list_responses(form_id: str, limit: int = 100, offset: int = 0):
    """
    List stored responses for a form. Results are sorted by submittedAt descending.
    """
    dir_path = _responses_dir(form_id)
    items: List[Dict] = []
    if os.path.exists(dir_path):
        for name in os.listdir(dir_path):
            if name.endswith(".json"):
                fpath = os.path.join(dir_path, name)
                try:
                    items.append(_read_json(fpath))
                except Exception:
                    continue
    items.sort(key=lambda d: d.get("submittedAt") or "", reverse=True)
    sliced = items[offset: offset + max(0, int(limit))]
    return {"count": len(items), "responses": sliced}
