from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Literal, Any
import logging
from datetime import datetime, timezone
import os
import json
import uuid
import urllib.parse
import urllib.request
import re
import shutil
import subprocess
try:
    import dns.resolver  # type: ignore
    _DNS_AVAILABLE = True
except Exception:
    dns = None  # type: ignore
    _DNS_AVAILABLE = False

# Email sender (Resend preferred)
try:
    from ..utils.email import render_email, send_email_html  # type: ignore
except Exception:
    from utils.email import render_email, send_email_html  # type: ignore

# Email validation
from email_validator import validate_email as _validate_email, EmailNotValidError as _EmailNotValidError
try:
    from disposable_email_domains import blocklist as _DISPOSABLE_BLOCKLIST  # type: ignore
    _DISPOSABLE_SET = set(map(str.lower, _DISPOSABLE_BLOCKLIST or []))
except Exception:
    _DISPOSABLE_SET = set()

# Common free email providers
_FREE_EMAIL_PROVIDERS = {
    'gmail.com','googlemail.com','yahoo.com','ymail.com','rocketmail.com','outlook.com','hotmail.com','live.com',
    'msn.com','aol.com','icloud.com','me.com','mac.com','protonmail.com','pm.me','mail.com','gmx.com','gmx.net',
    'zoho.com','yandex.com','yandex.ru','inbox.ru','list.ru','bk.ru','mail.ru'
}

# GeoIP via ip2geotools (no local database required)
from typing import Tuple
try:
    from ip2geotools.databases.noncommercial import DbIpCity  # type: ignore
    _GEO_LOOKUP_AVAILABLE = True
except Exception:
    DbIpCity = None  # type: ignore
    _GEO_LOOKUP_AVAILABLE = False

# Logger
logger = logging.getLogger("backend.builder")

# Firestore plan check (to gate Pro features on server)
try:
    import firebase_admin  # type: ignore
    from firebase_admin import firestore as _fs  # type: ignore
    _FS_AVAILABLE = True
except Exception:
    _FS_AVAILABLE = False

from typing import Optional as _Optional

def _is_pro_plan(user_id: _Optional[str]) -> bool:
    if not _FS_AVAILABLE or not user_id:
        return False
    try:
        doc = _fs.client().collection("users").document(user_id).get()
        data = doc.to_dict() or {}
        plan = str(data.get("plan") or "").lower()
        return plan in ("pro", "business", "enterprise")
    except Exception:
        return False


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


class VisualImage(BaseModel):
    id: str
    url: str
    # Position and size as percentages relative to the form preview container
    left: float = 0.0   # 0-100
    top: float = 0.0    # 0-100
    width: float = 20.0 # 0-100 (percentage of container width)
    # Optional explicit height percentage (when omitted, height is auto based on image's intrinsic ratio)
    height: Optional[float] = None  # 0-100
    zIndex: Optional[int] = 1
    rotation: Optional[float] = 0.0


class Branding(BaseModel):
    logo: Optional[str] = None  # data URL or external URL
    logoPosition: Literal["top", "bottom"] = "top"
    logoSize: Literal["small", "medium", "large"] = "medium"
    # Draggable visuals overlayed on the form
    visuals: Optional[List[VisualImage]] = []


class ThemeSchema(BaseModel):
    primaryColor: str = "#4f46e5"
    backgroundColor: str = "#ffffff"
    pageBackgroundColor: str = "#ffffff"
    textColor: str = "#111827"
    titleColor: str = "#000000"
    # Field label customization
    fieldLabelColor: str = "#cccccc"
    inputBgColor: str = "#ffffff"
    inputTextColor: str = "#111827"
    inputBorderColor: str = "#d1d5db"
    inputBorderRadius: int = 8
    # Persist builder border customization
    inputBorderWidth: int = 1
    inputBorderStyle: Literal["none", "solid", "dashed", "dotted", "double", "groove", "ridge", "inset", "outset"] = "solid"
    inputBorderSide: Literal["all", "top", "right", "bottom", "left"] = "all"
    # Optional input shadow
    inputShadowEnabled: bool = False
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
        "image",
        "video",
        "audio",
    ]
    required: bool = False
    placeholder: Optional[str] = None
    options: Optional[List[str]] = None
    step: Optional[int] = Field(default=1, ge=1)
    maxLength: Optional[int] = Field(default=None, gt=0)
    accept: Optional[str] = None
    multiple: Optional[bool] = None
    # Media-specific configuration
    mediaUrl: Optional[str] = None
    poster: Optional[str] = None  # video thumbnail
    caption: Optional[str] = None
    autoplay: Optional[bool] = None
    loop: Optional[bool] = None
    controls: Optional[bool] = None
    muted: Optional[bool] = None
    # Validation options for special field types
    # Full name
    fullNameRequireTwoWords: Optional[bool] = True
    # Password strength
    passwordMinLength: Optional[int] = 8
    passwordRequireUppercase: Optional[bool] = True
    passwordRequireLowercase: Optional[bool] = True
    passwordRequireNumber: Optional[bool] = True
    passwordRequireSpecial: Optional[bool] = False

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
    professionalEmailsOnly: bool = False
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
    allowedCountries: Optional[List[str]] = []  # ISO alpha-2 whitelist; when set, only these can submit
    # Duplicate submission prevention by IP
    preventDuplicateByIP: bool = False
    duplicateWindowHours: int = 24  # time window to consider duplicates
    # Custom domain configuration
    customDomain: Optional[str] = None
    customDomainVerified: bool = False
    sslVerified: bool = False
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None


# -----------------------------
# Helpers
# -----------------------------

EXTENDED_ALLOWED_TYPES = {
    "text",
    "textarea",
    "number",
    "price",
    "phone",
    "checkbox",
    "dropdown",
    "multiple",
    "date",
    "location",
    "address",
    "url",
    "file",
    # Sensitive/validated input types
    "full-name",
    "password",
    # Media display (non-interactive)
    "image",
    "video",
    "audio",
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
        if f.type == "password":
            try:
                if f.passwordMinLength is not None and int(f.passwordMinLength) < 1:
                    raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid passwordMinLength")
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid passwordMinLength")

    

def _create_id() -> str:
    return uuid.uuid4().hex


RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET_KEY") or os.getenv("RECAPTCHA_SECRET") or ""
# Custom domain target for CNAME verification
CUSTOM_DOMAIN_TARGET = (os.getenv("CUSTOM_DOMAIN_TARGET") or "api.cleanenroll.com").strip('.').lower()
# ACME/Certbot configuration
ACME_WEBROOT = os.getenv("ACME_WEBROOT") or os.path.join(os.getcwd(), "data", "acme")
ACME_CHALLENGE_DIR = os.path.join(ACME_WEBROOT, ".well-known", "acme-challenge")
os.makedirs(ACME_CHALLENGE_DIR, exist_ok=True)
CERTBOT_BIN = os.getenv("CERTBOT_BIN") or "certbot"
EMAIL_FOR_LE = os.getenv("LETSENCRYPT_EMAIL") or os.getenv("LE_EMAIL") or "admin@cleanenroll.com"

# --- Nginx helper templates & functions ---

def _nginx_conf_http(domain: str) -> str:
    return f"""
server {{
    listen 80;
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root {ACME_WEBROOT};
    }}

    return 301 https://$host$request_uri;
}}
""".strip()


def _nginx_conf_tls(domain: str) -> str:
    cert_base = f"/etc/letsencrypt/live/{domain}"
    return f"""
server {{
    listen 80;
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root {ACME_WEBROOT};
    }}

    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {domain};

    ssl_certificate     {cert_base}/fullchain.pem;
    ssl_certificate_key {cert_base}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    location /.well-known/acme-challenge/ {{
        root {ACME_WEBROOT};
    }}

    location / {{
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass {UPSTREAM_ADDR};
        proxy_read_timeout 60s;
    }}
}}
""".strip()


def _write_text(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _ensure_symlink(src: str, dst: str):
    try:
        if os.path.islink(dst) or os.path.exists(dst):
            try:
                if os.path.islink(dst) and os.readlink(dst) == src:
                    return
                os.remove(dst)
            except Exception:
                pass
        os.symlink(src, dst)
    except Exception:
        # On filesystems that don't support symlinks, copy the file
        try:
            shutil.copyfile(src, dst)
        except Exception:
            raise


def _shell(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)


def _nginx_test_and_reload() -> str:
    out = []
    t = _shell(NGINX_TEST_CMD)
    out.append(t.stdout or "")
    if t.returncode != 0:
        raise HTTPException(status_code=500, detail=f"nginx test failed:\n{(t.stdout or '')[-4000:]}")
    r = _shell(NGINX_RELOAD_CMD)
    out.append(r.stdout or "")
    if r.returncode != 0:
        raise HTTPException(status_code=500, detail=f"nginx reload failed:\n{(r.stdout or '')[-4000:]}")
    return "\n".join(out)
# Nginx & upstream configuration (env-overridable)
NGINX_SITES_AVAILABLE = os.getenv("NGINX_SITES_AVAILABLE") or "/etc/nginx/sites-available"
NGINX_SITES_ENABLED  = os.getenv("NGINX_SITES_ENABLED")  or "/etc/nginx/sites-enabled"
NGINX_BIN            = os.getenv("NGINX_BIN")            or "nginx"
NGINX_TEST_CMD       = os.getenv("NGINX_TEST_CMD")       or "nginx -t"
NGINX_RELOAD_CMD     = os.getenv("NGINX_RELOAD_CMD")     or "nginx -s reload"
UPSTREAM_ADDR        = os.getenv("UPSTREAM_ADDR")        or "http://127.0.0.1:8000"
# Optional DNS-01 configuration for Certbot (provider plugin)
CERTBOT_DNS_PROVIDER      = os.getenv("CERTBOT_DNS_PROVIDER")  # e.g., 'cloudflare'
CERTBOT_DNS_CREDENTIALS   = os.getenv("CERTBOT_DNS_CREDENTIALS")  # path to credentials file

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


def _normalize_domain(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    try:
        d = str(s).strip().lower()
        d = re.sub(r"^https?://", "", d)
        d = d.split("/")[0]
        d = d.strip('.')
        return d or None
    except Exception:
        return None


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
    if not _GEO_LOOKUP_AVAILABLE or not ip:
        return False, None
    try:
        result = DbIpCity.get(ip, api_key="free")  # type: ignore
        code = (getattr(result, "country", None) or "").upper()
        return True, code or None
    except Exception:
        return False, None


def _geo_from_ip(ip: str) -> Tuple[Optional[str], Optional[float], Optional[float]]:
    """Return (countryISO2, lat, lon) best-effort."""
    if not _GEO_LOOKUP_AVAILABLE or not ip:
        return None, None, None
    try:
        res = DbIpCity.get(ip, api_key="free")  # type: ignore
        country = (getattr(res, "country", None) or "").upper() or None
        lat = None
        lon = None
        try:
            lat = float(getattr(res, "latitude", None)) if getattr(res, "latitude", None) is not None else None
            lon = float(getattr(res, "longitude", None)) if getattr(res, "longitude", None) is not None else None
        except Exception:
            lat, lon = None, None
        return country, lat, lon
    except Exception:
        return None, None, None


# -----------------------------
# Routes
# -----------------------------

router = APIRouter(prefix="/api/builder", tags=["builder"]) 

# Use the shared limiter instance configured in utils.limiter
try:
    from ..utils.limiter import limiter  # type: ignore
except Exception:
    from utils.limiter import limiter  # type: ignore

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
    form_id = (cfg.id or "").strip() or _create_id()
    data = cfg.dict()
    # Preserve provided step values; default missing/invalid to 1
    for f in data.get("fields") or []:
        try:
            step_val = int(f.get("step") or 1)
            f["step"] = max(1, step_val)
        except Exception:
            f["step"] = 1
    # Normalize restrictedCountries/allowedCountries to upper-case ISO codes
    data["restrictedCountries"] = _normalize_country_list(data.get("restrictedCountries") or [])
    data["allowedCountries"] = _normalize_country_list(data.get("allowedCountries") or [])
    data["id"] = form_id
    data["createdAt"] = now
    data["updatedAt"] = now
    data["isPublished"] = bool(data.get("isPublished", False))
    # Custom domain normalization
    data["customDomain"] = _normalize_domain(data.get("customDomain"))
    data["customDomainVerified"] = bool(data.get("customDomainVerified")) and bool(data.get("customDomain"))
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
    # Normalize restrictedCountries/allowedCountries to upper-case ISO codes
    data["restrictedCountries"] = _normalize_country_list(data.get("restrictedCountries") or [])
    data["allowedCountries"] = _normalize_country_list(data.get("allowedCountries") or [])
    data["id"] = form_id
    prev = _read_json(path)
    # Normalize custom domain and reset verification if changed
    incoming_domain = _normalize_domain(data.get("customDomain"))
    prev_domain = _normalize_domain(prev.get("customDomain"))
    data["customDomain"] = incoming_domain
    if incoming_domain != prev_domain:
        data["customDomainVerified"] = False
    else:
        data["customDomainVerified"] = bool(prev.get("customDomainVerified"))
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
        # Also remove stored responses for this form (best-effort)
        try:
            resp_dir = os.path.join(RESPONSES_BASE_DIR, form_id)
            if os.path.exists(resp_dir):
                shutil.rmtree(resp_dir)
        except Exception:
            logger.exception("failed to delete responses for form %s", form_id)
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

    allowed = _normalize_country_list(form_data.get("allowedCountries") or [])
    restricted = _normalize_country_list(form_data.get("restrictedCountries") or [])

    ip = _client_ip(request)
    _, country = _country_from_ip(ip)
    print(f"[DEBUG] ip={ip}, country={country}, allowed={allowed}, restricted={restricted}")

    # Require valid country
    if not country:
        raise HTTPException(status_code=403, detail="Could not determine your location")

    # Enforce allowed countries whitelist when present
    if allowed and country not in allowed:
        logger.info("geo_check blocked (not allowed) id=%s ip=%s country=%s", form_id, ip, country)
        raise HTTPException(status_code=403, detail="Your IP location is restricted from submitting the form")

    # Enforce restricted blacklist
    if restricted and country in restricted:
        logger.info("geo_check blocked (restricted) id=%s ip=%s country=%s", form_id, ip, country)
        raise HTTPException(status_code=403, detail="Your IP location is restricted from submitting the form")

    logger.debug("geo_check allowed id=%s ip=%s country=%s", form_id, ip, country)
    return {"allowed": True, "country": country}



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
    """Send a notification email using the unified base template.
    Expected payload (flexible):
      { to: str,
        subject?: str,
        title?: str,
        preheader?: str,
        intro?: str,
        content_html?: str,  # preferred rich content block
        html?: str,          # legacy; treated as content_html
        formTitle?: str,     # legacy convenience
        summary?: str,       # legacy convenience
        cta_label?: str,
        cta_url?: str }
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")

    to = (payload.get("to") or "").strip()
    if not to:
        raise HTTPException(status_code=400, detail="Missing 'to' email")

    # Subject and title
    subject = (payload.get("subject") or "New form submission").strip()
    title = (payload.get("title") or subject).strip()

    # Legacy helpers
    form_title = (payload.get("formTitle") or "").strip()
    summary = (payload.get("summary") or "").strip()

    # Content assembly
    content_html = payload.get("content_html") or payload.get("html") or ""
    intro = (payload.get("intro") or (summary if summary else "")).strip()
    if (not content_html) and (form_title or summary):
        # Build a simple content block if only legacy fields are provided
        ft = form_title or "Form"
        sm = summary or "A new submission was received."
        content_html = (
            f"<div><p style='margin:0 0 12px;color:#d1d5db'>New submission: <strong>{ft}</strong></p>"
            f"<p style='margin:0;color:#d1d5db'>{sm}</p></div>"
        )

    preheader = (payload.get("preheader") or intro or "Automated notification from CleanEnroll").strip()

    ctx = {
        "subject": subject,
        "preheader": preheader,
        "title": title,
        "intro": intro,
        "content_html": content_html,
        "cta_label": (payload.get("cta_label") or "View details"),
        "cta_url": (payload.get("cta_url") or "https://cleanenroll.com/dashboard"),
    }

    try:
        html = render_email("base.html", ctx)
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
    # Determine if owner has Pro plan (fallback to Free if unknown)
    try:
        owner_id = str(form_data.get("userId") or "").strip() or None
    except Exception:
        owner_id = None
    is_pro = _is_pro_plan(owner_id)

    # Password protection enforcement
    try:
        if is_pro and bool(form_data.get("passwordProtectionEnabled")) and form_data.get("passwordHash"):
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

    # Determine client IP
    ip = _client_ip(request)

    # Geo restriction enforcement (allowed whitelist takes precedence when provided)
    allowed = _normalize_country_list(form_data.get("allowedCountries") or []) if is_pro else []
    restricted = _normalize_country_list(form_data.get("restrictedCountries") or []) if is_pro else []
    if allowed:
        _, country = _country_from_ip(ip)
        if country and country not in allowed:
            raise HTTPException(status_code=403, detail="Your IP location is restricted from submitting the form, We're sorry about that")
    if restricted:
        _, country = _country_from_ip(ip)
        if country and country in restricted:
            raise HTTPException(status_code=403, detail="Your IP location is restricted from submitting the form, We're sorry about that")

    # Duplicate submission check by IP within a time window
    if is_pro and bool(form_data.get("preventDuplicateByIP")):
        try:
            window_hours = int(form_data.get("duplicateWindowHours") or 24)
        except Exception:
            window_hours = 24
        try:
            from datetime import timedelta
            threshold = datetime.utcnow() - timedelta(hours=max(1, window_hours))
            # Ensure IP is available
            ip = ip or _client_ip(request)
            if ip:
                dir_path = _responses_dir(form_id)
                if os.path.exists(dir_path):
                    for name in os.listdir(dir_path):
                        if not name.endswith(".json"):
                            continue
                        fpath = os.path.join(dir_path, name)
                        try:
                            rec = _read_json(fpath)
                            rec_ip = rec.get("clientIp") or rec.get("ip") or None
                            ts = rec.get("submittedAt") or ""
                            if rec_ip == ip:
                                dt = datetime.fromisoformat(ts)
                                if dt >= threshold:
                                    raise HTTPException(status_code=429, detail="Duplicate submission detected from this IP. Please try again later.")
                        except HTTPException:
                            raise
                        except Exception:
                            continue
        except HTTPException:
            raise
        except Exception:
            # Fail open on dedupe errors
            pass

    # reCAPTCHA verification when enabled
    if is_pro and form_data.get("recaptchaEnabled"):
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
    if is_pro and form_data.get("emailValidationEnabled"):
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
                # Syntax + MX deliverability
                _validate_email(addr, check_deliverability=True)
                # Enforce professional/business emails if enabled
                if bool(form_data.get("professionalEmailsOnly")):
                    try:
                        domain = addr.split('@', 1)[1].strip().lower()
                    except Exception:
                        domain = ''
                    if not domain:
                        raise HTTPException(status_code=400, detail=f"Invalid email for field '{lab}': domain missing")
                    # Reject if domain is free provider or disposable provider
                    if domain in _FREE_EMAIL_PROVIDERS or domain in _DISPOSABLE_SET:
                        raise HTTPException(status_code=400, detail=f"Please use your professional work email address for '{lab}'. Personal or disposable email domains are not accepted.")
            except _EmailNotValidError as e:
                raise HTTPException(status_code=400, detail=f"Invalid email for field '{lab}': {str(e)}")

    # Field-level validations for full-name and password
    try:
        fields_def = form_data.get("fields") or []
        if isinstance(payload, dict):
            for f in fields_def:
                try:
                    ftype = f.get("type")
                    fid = str(f.get("id"))
                    label = str(f.get("label") or "")
                except Exception:
                    continue
                val = payload.get(fid)
                if val is None and label:
                    val = payload.get(label)
                # Full name: require at least two words with at least 2 letters each (basic heuristic)
                if ftype == "full-name":
                    if val:
                        s = str(val).strip()
                        parts = [p for p in re.split(r"\s+", s) if p]
                        if len(parts) < 2 or any(len(p) < 2 for p in parts[:2]):
                            raise HTTPException(status_code=400, detail=f"Please enter a full name (first and last) for '{label}'.")
                    elif f.get("required"):
                        raise HTTPException(status_code=400, detail=f"'{label}' is required.")
                # Password: enforce strength based on field options or defaults
                elif ftype == "password":
                    if val:
                        s = str(val)
                        try:
                            min_len = max(1, int(f.get("passwordMinLength") or 8))
                        except Exception:
                            min_len = 8
                        req_u = bool(f.get("passwordRequireUppercase", True))
                        req_l = bool(f.get("passwordRequireLowercase", True))
                        req_d = bool(f.get("passwordRequireNumber", True))
                        req_s = bool(f.get("passwordRequireSpecial", False))
                        if len(s) < min_len:
                            raise HTTPException(status_code=400, detail=f"Password for '{label}' must be at least {min_len} characters.")
                        if req_u and not re.search(r"[A-Z]", s):
                            raise HTTPException(status_code=400, detail=f"Password for '{label}' must contain an uppercase letter.")
                        if req_l and not re.search(r"[a-z]", s):
                            raise HTTPException(status_code=400, detail=f"Password for '{label}' must contain a lowercase letter.")
                        if req_d and not re.search(r"[0-9]", s):
                            raise HTTPException(status_code=400, detail=f"Password for '{label}' must contain a number.")
                        if req_s and not re.search(r"[^A-Za-z0-9]", s):
                            raise HTTPException(status_code=400, detail=f"Password for '{label}' must contain a special character.")
                    elif f.get("required"):
                        raise HTTPException(status_code=400, detail=f"'{label}' is required.")
    except HTTPException:
        raise
    except Exception:
        # Fail closed on malformed validation config
        raise HTTPException(status_code=400, detail="Validation failed for one or more fields")

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
        # Geo enrich from client IP
        country_code, lat, lon = _geo_from_ip(ip)
        record = {
            "responseId": response_id,
            "formId": form_id,
            "submittedAt": submitted_at,
            "clientIp": ip,
            "country": country_code,
            "lat": lat,
            "lon": lon,
            "answers": answers,
        }
        _write_json(_new_response_path(form_id, submitted_at, response_id), record)
        # Attempt Google Sheets append if syncing is enabled for this form
        try:
            # try import via package-aware path first
            try:
                from .google_sheets import try_append_submission_for_form  # type: ignore
            except Exception:
                from routers.google_sheets import try_append_submission_for_form  # type: ignore
            owner_id = str(form_data.get("userId") or "").strip() or None
            if owner_id:
                try_append_submission_for_form(owner_id, form_id, record)
        except Exception:
            logger.exception("google_sheets sync append failed form_id=%s", form_id)
        # Optionally return responseId to the client
        resp["responseId"] = response_id  # type: ignore
    except Exception:
        # Swallow persistence errors to not break client submission flow
        logger.exception("submit_form persistence error id=%s", form_id)

    logger.info("form submitted id=%s response_id=%s", form_id, resp.get("responseId"))
    return resp

@router.post("/forms/{form_id}/custom-domain/verify")
async def verify_custom_domain(form_id: str, payload: Dict = None, domain: Optional[str] = None):
    """
    Verify custom domain by resolving its CNAME to our target. Also prevent duplicate domain
    assignments across forms and attempt a simple HTTPS check to report SSL status.
    If the form JSON does not exist yet, allow passing the domain to create a minimal stub so
    verification can proceed.
    """
    path = _form_path(form_id)
    data: Dict = {}
    if os.path.exists(path):
        data = _read_json(path)
    else:
        inbound_domain = _normalize_domain(
            domain
            or ((payload or {}).get("customDomain") if isinstance(payload, dict) else None)
            or ((payload or {}).get("domain") if isinstance(payload, dict) else None)
        )
        if inbound_domain:
            now = datetime.utcnow().isoformat()
            data = {
                "id": form_id,
                "title": "Untitled Form",
                "subtitle": "",
                "customDomain": inbound_domain,
                "customDomainVerified": False,
                "sslVerified": False,
                "createdAt": now,
                "updatedAt": now,
            }
            _write_json(path, data)
        else:
            raise HTTPException(status_code=404, detail="Form not found")

    domain_val = _normalize_domain(
        data.get("customDomain")
        or domain
        or ((payload or {}).get("customDomain") if isinstance(payload, dict) else None)
        or ((payload or {}).get("domain") if isinstance(payload, dict) else None)
    )
    if not domain_val:
        raise HTTPException(status_code=400, detail="No custom domain configured")

    # Enforce uniqueness: domain cannot be assigned to another form
    try:
        for name in os.listdir(BACKING_DIR):
            if not name.endswith('.json'):
                continue
            other_path = os.path.join(BACKING_DIR, name)
            try:
                other = _read_json(other_path)
            except Exception:
                continue
            oid = str(other.get('id') or name.replace('.json',''))
            odomain = _normalize_domain(other.get('customDomain'))
            if odomain and odomain == domain_val and oid != form_id:
                raise HTTPException(status_code=409, detail=f"This domain is already connected to another form (id={oid}). Remove it there first.")
    except HTTPException:
        raise
    except Exception:
        pass

    if not _DNS_AVAILABLE:
        raise HTTPException(status_code=500, detail="DNS library not available on server")

    # Resolve CNAME and validate target
    try:
        answers = dns.resolver.resolve(domain_val + ".", "CNAME")  # type: ignore[attr-defined]
        targets = [str(rdata.target).rstrip('.').lower() for rdata in answers]
        ok = any(t == CUSTOM_DOMAIN_TARGET for t in targets)
        if not ok:
            raise HTTPException(status_code=400, detail=f"CNAME for {domain_val} must point to {CUSTOM_DOMAIN_TARGET}")

        # Simple SSL check via HTTPS HEAD/GET
        ssl_ok = False
        try:
            req = urllib.request.Request(url=f"https://{domain_val}", method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:  # type: ignore
                ssl_ok = 200 <= getattr(resp, 'status', 200) < 400
        except Exception:
            try:
                # Fallback to GET if HEAD blocked
                with urllib.request.urlopen(f"https://{domain_val}", timeout=6) as resp:  # type: ignore
                    ssl_ok = 200 <= getattr(resp, 'status', 200) < 400
            except Exception:
                ssl_ok = False

        # Persist verification and SSL state
        data["customDomainVerified"] = True
        data["sslVerified"] = bool(ssl_ok)
        data["customDomain"] = domain_val
        data["updatedAt"] = datetime.utcnow().isoformat()
        _write_json(path, data)
        return {"verified": True, "domain": domain_val, "target": CUSTOM_DOMAIN_TARGET, "sslVerified": bool(ssl_ok)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"DNS verification failed: {e}")

@router.post("/forms/{form_id}/custom-domain/issue-cert")
async def issue_cert(form_id: str):
    """Automate per-domain certificate issuance and Nginx config deployment.
    Steps:
      1) Write HTTP-only vhost for ACME challenges and reload Nginx
      2) Issue certificate via Certbot (webroot by default, DNS-01 if configured)
      3) Write HTTPS vhost with issued cert and reload Nginx
      4) Mark sslVerified=true in form record
    """
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    data = _read_json(path)

    domain_val = _normalize_domain(data.get("customDomain"))
    if not domain_val:
        raise HTTPException(status_code=400, detail="No custom domain configured")
    if not data.get("customDomainVerified"):
        raise HTTPException(status_code=400, detail="Domain not verified yet")

    # 1) Ensure ACME webroot exists and deploy HTTP-only conf
    os.makedirs(ACME_CHALLENGE_DIR, exist_ok=True)
    conf_name = f"custom_{domain_val}.conf"
    avail_path = os.path.join(NGINX_SITES_AVAILABLE, conf_name)
    enabled_path = os.path.join(NGINX_SITES_ENABLED, conf_name)
    try:
        _write_text(avail_path, _nginx_conf_http(domain_val))
        _ensure_symlink(avail_path, enabled_path)
        http_reload_out = _nginx_test_and_reload()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write HTTP vhost or reload Nginx: {e}")

    # 2) Run Certbot (webroot by default; DNS provider if configured)
    cert_cmd = [CERTBOT_BIN, "certonly", "--agree-tos", "--non-interactive", "--email", EMAIL_FOR_LE]
    if CERTBOT_DNS_PROVIDER and CERTBOT_DNS_CREDENTIALS:
        cert_cmd += [f"-a", f"dns-{CERTBOT_DNS_PROVIDER}"]
        # Provider-specific flags typically: --dns-<provider>-credentials <file>
        cert_cmd += [f"--dns-{CERTBOT_DNS_PROVIDER}-credentials", CERTBOT_DNS_CREDENTIALS]
    else:
        cert_cmd += ["--webroot", "-w", ACME_WEBROOT]
    cert_cmd += ["-d", domain_val]

    try:
        proc = subprocess.run(cert_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
        cert_out = proc.stdout or ""
        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Certbot failed:\n{cert_out[-4000:]}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Certbot execution error: {e}")

    # 3) Deploy HTTPS vhost and reload Nginx
    try:
        _write_text(avail_path, _nginx_conf_tls(domain_val))
        https_reload_out = _nginx_test_and_reload()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write HTTPS vhost or reload Nginx: {e}")

    # 4) Persist SSL verified = True
    data["sslVerified"] = True
    data["updatedAt"] = datetime.utcnow().isoformat()
    _write_json(path, data)

    return {
        "success": True,
        "domain": domain_val,
        "nginxHttpReload": http_reload_out,
        "nginxHttpsReload": https_reload_out,
        "certbot": cert_out[-4000:],
        "sitesAvailable": avail_path,
        "sitesEnabled": enabled_path,
    }

# ---- 3. ACME challenge helper (optional) ----
@router.post("/acme/challenge")
async def acme_write_challenge(payload: Dict = None):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")
    token = str(payload.get("token") or "").strip()
    content = str(payload.get("content") or "").strip()
    if not token or not content:
        raise HTTPException(status_code=400, detail="Missing token or content")
    if not re.fullmatch(r"[A-Za-z0-9_\-.]+", token):
        raise HTTPException(status_code=400, detail="Invalid token format")

    try:
        os.makedirs(ACME_CHALLENGE_DIR, exist_ok=True)
        fpath = os.path.join(ACME_CHALLENGE_DIR, token)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write challenge: {e}")


@router.get("/forms/{form_id}/responses")
async def list_responses(
    form_id: str,
    limit: int = 100,
    offset: int = 0,
    from_ts: Optional[str] = Query(default=None, alias="from", description="ISO datetime lower bound (inclusive)"),
    to_ts: Optional[str] = Query(default=None, alias="to", description="ISO datetime upper bound (inclusive)"),
):
    """
    List stored responses for a form. Results are sorted by submittedAt descending.
    Optional query params:
      - from (ISO datetime): include responses with submittedAt >= this
      - to (ISO datetime): include responses with submittedAt <= this
    """
    def _parse_bound_ms(val: Optional[str]) -> Optional[int]:
        if not val:
            return None
        try:
            s = str(val).strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except Exception:
            return None

    def _submitted_ms(rec: Dict) -> int:
        ts = rec.get("submittedAt") or ""
        try:
            s = str(ts).strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except Exception:
            return 0

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

    # Apply server-side date filters when provided
    lower = _parse_bound_ms(from_ts)
    upper = _parse_bound_ms(to_ts)
    if (lower is not None) or (upper is not None):
        filtered: List[Dict] = []
        for rec in items:
            ms = _submitted_ms(rec)
            if (lower is not None) and (ms < lower):
                continue
            if (upper is not None) and (ms > upper):
                continue
            filtered.append(rec)
        items = filtered

    # Sort by submittedAt desc (fallback to 0 when missing)
    items.sort(key=lambda d: _submitted_ms(d), reverse=True)

    # Pagination
    sliced = items[offset: offset + max(0, int(limit))]
    return {"count": len(items), "responses": sliced}
