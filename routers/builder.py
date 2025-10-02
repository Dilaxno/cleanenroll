from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
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
import requests
import zipfile
import io
import boto3
from botocore.client import Config as BotoConfig
try:
    import dns.resolver  # type: ignore
    _DNS_AVAILABLE = True
except Exception:
    dns = None  # type: ignore
    _DNS_AVAILABLE = False

# WHOIS for domain reputation/age checks
try:
    import whois as _whois  # type: ignore
    _WHOIS_AVAILABLE = True
except Exception:
    _whois = None  # type: ignore
    _WHOIS_AVAILABLE = False

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

# GeoIP providers: Geoapify preferred, ip2geotools as optional fallback
from typing import Tuple
try:
    from ip2geotools.databases.noncommercial import DbIpCity  # type: ignore
    _DBIPCITY_AVAILABLE = True
except Exception:
    DbIpCity = None  # type: ignore
    _DBIPCITY_AVAILABLE = False

GEOAPIFY_API_KEY = os.getenv("GEOAPIFY_API_KEY") or ""
_GEOAPIFY_AVAILABLE = bool(GEOAPIFY_API_KEY)
_GEO_LOOKUP_AVAILABLE = bool(_GEOAPIFY_AVAILABLE or _DBIPCITY_AVAILABLE)

# Logger
logger = logging.getLogger("backend.builder")
# Log geo lookup availability at import time
try:
    logger.info("geo: providers geoapify=%s dbipcity=%s", _GEOAPIFY_AVAILABLE, _DBIPCITY_AVAILABLE)
    if not _GEO_LOOKUP_AVAILABLE:
        logger.warning("geo: no geolocation provider available; country/lat/lon enrichment disabled")
except Exception:
    pass

# Firestore plan check (to gate Pro features on server)
try:
    import firebase_admin  # type: ignore
    from firebase_admin import firestore as _fs  # type: ignore
    _FS_AVAILABLE = True
except Exception:
    _FS_AVAILABLE = False

from typing import Optional as _Optional

def _is_pro_plan(user_id: _Optional[str]) -> bool:
    if not user_id:
        return False
    # Prefer Supabase when configured
    if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
        try:
            # Try by id column
            rows = _sb_get("users", {"select": "plan", "id": f"eq.{user_id}", "limit": "1"})
            if not rows:
                # Fallback to uid column naming
                rows = _sb_get("users", {"select": "plan", "uid": f"eq.{user_id}", "limit": "1"})
            if rows:
                plan = str((rows[0] or {}).get("plan") or "").lower()
                return plan in ("pro", "business", "enterprise")
        except Exception:
            return False
        return False
    # Fallback: Firestore when Supabase is not configured
    if not _FS_AVAILABLE:
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

# Analytics storage (file-based aggregation)
ANALYTICS_BASE_DIR = os.path.join(os.getcwd(), "data", "analytics")
os.makedirs(ANALYTICS_BASE_DIR, exist_ok=True)

# Plan-based upload limits
FREE_MAX_UPLOAD_BYTES = 50 * 1024 * 1024      # 50MB for Free plan
PRO_MAX_UPLOAD_BYTES = 1024 * 1024 * 1024     # 1GB for Pro/paid plans

# Cloudflare R2 configuration (S3-compatible)
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID") or os.getenv("CLOUDFLARE_R2_ACCOUNT_ID") or ""
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID") or os.getenv("CLOUDFLARE_R2_ACCESS_KEY_ID") or ""
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY") or os.getenv("CLOUDFLARE_R2_SECRET_ACCESS_KEY") or ""
R2_BUCKET = os.getenv("R2_BUCKET") or "formbg"
R2_PUBLIC_BASE = os.getenv("R2_PUBLIC_BASE") or os.getenv("R2_PUBLIC_DOMAIN") or "https://pub-e30045e3902945f4ada02414d0573c3b.r2.dev"

# Supabase configuration (REST via service role key)
SUPABASE_URL = (os.getenv("SUPABASE_URL") or "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY") or ""


def _sb_headers() -> Dict[str, str]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase is not configured on server")
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Prefer": "return=representation"
    }


def _sb_get(table: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    try:
        resp = requests.get(url, headers=_sb_headers(), params=params, timeout=15)
        if resp.status_code == 406:
            return []
        if not resp.ok:
            raise HTTPException(status_code=502, detail=f"Supabase select failed: {resp.text}")
        return resp.json() if resp.text else []
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Supabase error: {e}")


def _sb_upsert(table: str, row: Dict[str, Any], on_conflict: Optional[str] = None) -> Dict[str, Any]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    if on_conflict:
        url += f"?on_conflict={on_conflict}"
    headers = _sb_headers().copy()
    headers["Prefer"] = headers.get("Prefer", "") + ",resolution=merge-duplicates"
    try:
        resp = requests.post(url, headers=headers, json=row, timeout=15)
        if not resp.ok:
            raise HTTPException(status_code=502, detail=f"Supabase upsert failed: {resp.text}")
        data = resp.json() if resp.text else []
        if isinstance(data, list) and data:
            return data[0]
        return row
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Supabase error: {e}")


def _r2_client():
    if not (R2_ACCOUNT_ID and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY):
        raise HTTPException(status_code=500, detail="R2 is not configured on server")
    endpoint = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=BotoConfig(signature_version="s3v4"),
        region_name="auto",
    )


def _public_url_for_key(key: str) -> str:
    base = (R2_PUBLIC_BASE or "").strip()
    if not base:
        return key
    if not base.startswith("http"):
        base = "https://" + base
    try:
        pr = urlparse(base)
        origin = f"{pr.scheme}://{pr.netloc}".rstrip("/")
    except Exception:
        origin = base.rstrip("/")
    # For r2.dev public domains, the bucket is already bound; do not include bucket or any extra path
    if ".r2.dev" in origin:
        return f"{origin}/{key}"
    # Default: append key to base origin
    return f"{origin}/{key}"

# Normalize any presigned Cloudflare R2 URL to a permanent public URL
# If the input is already public or a non-R2 URL, returns it unchanged (without query string)
from urllib.parse import urlparse, urlunparse

def _normalize_bg_public_url(u: Optional[str]) -> Optional[str]:
    if not u:
        return u
    try:
        s = str(u).strip()
        pr = urlparse(s)
        # strip query/fragment always
        pr = pr._replace(query='', fragment='')
        host = (pr.netloc or '').lower()
        if '.r2.cloudflarestorage.com' in host:
            # Path format: /<bucket>/<key>
            parts = (pr.path or '/').split('/', 2)
            if len(parts) >= 3:
                # bucket = parts[1]
                key = parts[2]
                return _public_url_for_key(key)
            # Fallback: keep URL without query
            return urlunparse(pr)
        # Already public or other host: return without query
        return urlunparse(pr)
    except Exception:
        return u

def _analytics_countries_path(form_id: str) -> str:
    return os.path.join(ANALYTICS_BASE_DIR, form_id, "countries.json")

def _load_analytics_countries(form_id: str) -> Dict:
    path = _analytics_countries_path(form_id)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"total": {}, "daily": {}}
    return {"total": {}, "daily": {}}

def _save_analytics_countries(form_id: str, data: Dict) -> None:
    path = _analytics_countries_path(form_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.exception("analytics countries save failed form_id=%s err=%s", form_id, e)


def _analytics_increment_country(form_id: str, country_iso2: Optional[str], submitted_at_iso: str) -> None:
    if not country_iso2:
        return
    try:
        iso = str(country_iso2 or "").strip().upper()
        if not iso:
            return
        day_key = (submitted_at_iso or "").strip()
        try:
            if day_key.endswith("Z"):
                day_key = day_key[:-1] + "+00:00"
            dt = datetime.fromisoformat(day_key)
            day_key = dt.date().isoformat()
        except Exception:
            day_key = (submitted_at_iso or "")[:10]
        data = _load_analytics_countries(form_id)
        total = data.get("total") or {}
        daily = data.get("daily") or {}
        total[iso] = int(total.get(iso, 0)) + 1
        day_bucket = daily.get(day_key) or {}
        day_bucket[iso] = int(day_bucket.get(iso, 0)) + 1
        daily[day_key] = day_bucket
        data["total"] = total
        data["daily"] = daily
        data["updatedAt"] = datetime.utcnow().isoformat()
        _save_analytics_countries(form_id, data)
    except Exception:
        logger.exception("analytics countries increment error form_id=%s", form_id)

# Geo data local cache directory and file
WORLD_GEO_DIR = os.path.join(os.getcwd(), "data", "geo")
os.makedirs(WORLD_GEO_DIR, exist_ok=True)
_WORLD_COUNTRIES_FILE = os.path.join(WORLD_GEO_DIR, "world-countries.geo.json")


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


class ThemeSchema(BaseModel):
    primaryColor: str = "#4f46e5"
    backgroundColor: str = "#ffffff"
    pageBackgroundColor: str = "#ffffff"
    # Background image settings for the page (behind the form)
    pageBackgroundImage: Optional[str] = None
    pageBackgroundImageSize: Optional[Literal["cover", "contain"]] = "cover"
    pageBackgroundImagePosition: Optional[str] = "center"
    pageBackgroundImageRepeat: Optional[Literal["no-repeat", "repeat", "repeat-x", "repeat-y"]] = "no-repeat"
    pageBackgroundDim: int = Field(default=0, ge=0, le=80)
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
    # Font settings (persist custom or Google font)
    fontFamily: Optional[str] = "Inter"
    fontUrl: Optional[str] = None
    customFontUrl: Optional[str] = None
    customFontName: Optional[str] = None
    customFontFormat: Optional[str] = None


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
        "age",
        "location",
        "address",
        "url",
        "email",
        "file",
        # Extended input types (supported server-side)
        "price",
        "phone",
        "full-name",
        "password",
        # Media display (non-interactive)
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
    # UI language for this form (ISO code like 'en', 'es', 'fr', ...)
    language: Optional[str] = "en"
    thankYouMessage: str = "Thank you for your submission! We'll get back to you soon."
    redirect: RedirectConfig = RedirectConfig()
    emailValidationEnabled: bool = False
    professionalEmailsOnly: bool = False
    # Block role-based generic inboxes (admin@, support@, info@, etc.)
    blockRoleEmails: bool = False
    # Advanced email reputation checks (Pro)
    emailRejectBadReputation: bool = False
    minDomainAgeDays: int = 30
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
    # Submission limit (0 or None = unlimited)
    submissionLimit: Optional[int] = None
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
    "age",
    "location",
    "address",
    "url",
    "email",
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
# Certbot writable directories (override defaults to avoid permission issues)
CERTBOT_CONFIG_DIR = os.getenv("CERTBOT_CONFIG_DIR") or os.path.join(os.getcwd(), "data", "letsencrypt", "config")
CERTBOT_WORK_DIR   = os.getenv("CERTBOT_WORK_DIR")   or os.path.join(os.getcwd(), "data", "letsencrypt", "work")
CERTBOT_LOGS_DIR   = os.getenv("CERTBOT_LOGS_DIR")   or os.path.join(os.getcwd(), "data", "letsencrypt", "logs")
# Ensure directories exist
os.makedirs(CERTBOT_CONFIG_DIR, exist_ok=True)
os.makedirs(CERTBOT_WORK_DIR, exist_ok=True)
os.makedirs(CERTBOT_LOGS_DIR, exist_ok=True)

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

# -----------------------------
# Email reputation helpers
# -----------------------------

# Common role-based local-part prefixes
_ROLE_BASED_PREFIXES = {
    'admin','administrator','hostmaster','webmaster','postmaster','root','support','info','sales','contact','help','noreply','no-reply','abuse','billing','security','office','hr'
}

def _is_role_based_email(email: str) -> bool:
    try:
        s = str(email or '').strip().lower()
        if '@' not in s:
            return False
        local = s.split('@', 1)[0]
        if not local:
            return False
        import re as _re
        base = _re.split(r"[+._]", local)[0]  # support+team, info.news
        if base in _ROLE_BASED_PREFIXES or local in _ROLE_BASED_PREFIXES:
            return True
        for p in _ROLE_BASED_PREFIXES:
            if local == p:
                return True
            if local.startswith(p):
                nxt = local[len(p):len(p)+1]
                if nxt == '' or _re.match(r"[\d+._-]", nxt):
                    return True
        return False
    except Exception:
        return False

def _spamhaus_listed(domain: str) -> Optional[bool]:
    """Check domain reputation using Spamhaus DBL (domains).
    Returns True if listed (bad), False if not listed (good), None on error/timeouts.
    """
    if not _DNS_AVAILABLE or not domain:
        return None
    try:
        # Query Spamhaus DBL for the domain
        q = f"{domain}.dbl.spamhaus.org"
        dns.resolver.resolve(q, "A")  # type: ignore[attr-defined]
        return True
    except Exception as e:
        try:
            NXDOMAIN = getattr(dns.resolver, 'NXDOMAIN', None)
            NoAnswer = getattr(dns.resolver, 'NoAnswer', None)
            Timeout = getattr(dns.resolver, 'Timeout', None)
            NoNameservers = getattr(dns.resolver, 'NoNameservers', None)
            if NXDOMAIN and isinstance(e, NXDOMAIN):
                return False
            if NoAnswer and isinstance(e, NoAnswer):
                return False
            if NoNameservers and isinstance(e, NoNameservers):
                return None
            if Timeout and isinstance(e, Timeout):
                return None
        except Exception:
            pass
        return None


def _domain_age_days(domain: str) -> Optional[int]:
    """Return domain age in days using WHOIS; None if unknown/error."""
    if not _WHOIS_AVAILABLE or not domain:
        return None
    try:
        data = _whois.whois(domain)  # type: ignore[attr-defined]
        created = getattr(data, 'creation_date', None) or getattr(data, 'created', None)
        from datetime import datetime, timezone
        def _parse_date(x):
            if isinstance(x, datetime):
                return x if x.tzinfo is not None else x.replace(tzinfo=timezone.utc)
            if isinstance(x, str):
                s = x.strip()
                try:
                    # Handle ISO and trailing Z
                    return datetime.fromisoformat(s.replace('Z', '+00:00'))
                except Exception:
                    pass
                for fmt in ("%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
                    try:
                        dt = datetime.strptime(s, fmt)
                        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        continue
            return None
        # Some registries return a list; pick the earliest reasonable date
        if isinstance(created, list):
            dates = [d for d in ([_parse_date(c) for c in created] if created else []) if d is not None]
            created_dt = min(dates) if dates else None
        else:
            created_dt = _parse_date(created)
        if not created_dt:
            return None
        now = datetime.now(timezone.utc)
        delta = now - created_dt
        days = int(delta.total_seconds() // 86400)
        return max(0, days)
    except Exception:
        return None


def _has_spf(domain: str) -> Optional[bool]:
    """Check if domain publishes an SPF record (TXT containing v=spf1)."""
    if not _DNS_AVAILABLE or not domain:
        return None
    try:
        records = dns.resolver.resolve(domain, "TXT")  # type: ignore[attr-defined]
        for r in records:
            try:
                txt = "".join([p.decode('utf-8', 'ignore') if isinstance(p, (bytes, bytearray)) else str(p) for p in getattr(r, 'strings', [])])
            except Exception:
                txt = str(r)
            if "v=spf1" in txt.lower():
                return True
        return False
    except Exception as e:
        try:
            NXDOMAIN = getattr(dns.resolver, 'NXDOMAIN', None)
            NoAnswer = getattr(dns.resolver, 'NoAnswer', None)
            Timeout = getattr(dns.resolver, 'Timeout', None)
            if NXDOMAIN and isinstance(e, NXDOMAIN):
                return False
            if NoAnswer and isinstance(e, NoAnswer):
                return False
            if Timeout and isinstance(e, Timeout):
                return None
        except Exception:
            pass
        return None


def _has_dmarc(domain: str) -> Optional[bool]:
    """Check if domain publishes a DMARC record (TXT at _dmarc.domain)."""
    if not _DNS_AVAILABLE or not domain:
        return None
    try:
        name = f"_dmarc.{domain}"
        records = dns.resolver.resolve(name, "TXT")  # type: ignore[attr-defined]
        for r in records:
            try:
                txt = "".join([p.decode('utf-8', 'ignore') if isinstance(p, (bytes, bytearray)) else str(p) for p in getattr(r, 'strings', [])])
            except Exception:
                txt = str(r)
            if "v=dmarc1" in txt.lower():
                return True
        return False
    except Exception as e:
        try:
            NXDOMAIN = getattr(dns.resolver, 'NXDOMAIN', None)
            NoAnswer = getattr(dns.resolver, 'NoAnswer', None)
            Timeout = getattr(dns.resolver, 'Timeout', None)
            if NXDOMAIN and isinstance(e, NXDOMAIN):
                return False
            if NoAnswer and isinstance(e, NoAnswer):
                return False
            if Timeout and isinstance(e, Timeout):
                return None
        except Exception:
            pass
        return None


def _has_any_dkim(domain: str) -> Optional[bool]:
    """Attempt to detect DKIM by checking common selectors (best-effort)."""
    if not _DNS_AVAILABLE or not domain:
        return None
    selectors = ["default", "selector1", "selector2", "google", "mail", "smtp"]
    try:
        for sel in selectors:
            name = f"{sel}._domainkey.{domain}"
            try:
                records = dns.resolver.resolve(name, "TXT")  # type: ignore[attr-defined]
                for r in records:
                    try:
                        txt = "".join([p.decode('utf-8', 'ignore') if isinstance(p, (bytes, bytearray)) else str(p) for p in getattr(r, 'strings', [])])
                    except Exception:
                        txt = str(r)
                    if "v=dkim1" in txt.lower():
                        return True
            except Exception:
                continue
        return False
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
    if not ip:
        logger.debug("geo: _country_from_ip skipped ip=%s", ip)
        return False, None
    # Prefer Geoapify when configured
    if _GEOAPIFY_AVAILABLE:
        try:
            url = (
                "https://api.geoapify.com/v1/ipinfo?"
                + urllib.parse.urlencode({"ip": ip, "apiKey": GEOAPIFY_API_KEY})
            )
            req = urllib.request.Request(url, headers={
                "User-Agent": "CleanEnroll/1.0 (+https://cleanenroll.com)",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=6) as resp:  # type: ignore
                raw = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(raw) if raw else {}
            # Attempt common paths for ISO-2
            country = None
            try:
                cobj = data.get("country") if isinstance(data, dict) else None
                if isinstance(cobj, dict):
                    country = cobj.get("iso_code") or cobj.get("iso") or cobj.get("code") or cobj.get("country_code")
            except Exception:
                pass
            if not country:
                country = data.get("country_code") or data.get("country")
            cc = (str(country or "").strip().upper() or None)
            logger.debug("geo: _country_from_ip (geoapify) ip=%s country=%s", ip, cc)
            return (cc is not None), cc
        except Exception as e:
            logger.warning("geo: _country_from_ip geoapify failed ip=%s err=%s", ip, e)
            # fallthrough to fallback
    # Fallback: DbIpCity when importable
    if DbIpCity is not None:
        try:
            result = DbIpCity.get(ip, api_key="free")  # type: ignore
            code = (getattr(result, "country", None) or "").upper()
            logger.debug("geo: _country_from_ip (dbipcity) ip=%s country=%s", ip, code or None)
            return True, code or None
        except Exception as e:
            logger.warning("geo: _country_from_ip dbipcity failed ip=%s err=%s", ip, e)
    return False, None


def _geo_from_ip(ip: str) -> Tuple[Optional[str], Optional[float], Optional[float]]:
    """Return (countryISO2, lat, lon) best-effort."""
    if not ip:
        logger.debug("geo: _geo_from_ip skipped ip=%s", ip)
        return None, None, None
    # Prefer Geoapify when configured
    if _GEOAPIFY_AVAILABLE:
        try:
            url = (
                "https://api.geoapify.com/v1/ipinfo?"
                + urllib.parse.urlencode({"ip": ip, "apiKey": GEOAPIFY_API_KEY})
            )
            req = urllib.request.Request(url, headers={
                "User-Agent": "CleanEnroll/1.0 (+https://cleanenroll.com)",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=6) as resp:  # type: ignore
                raw = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(raw) if raw else {}
            # Extract country code
            cc = None
            try:
                cobj = data.get("country") if isinstance(data, dict) else None
                if isinstance(cobj, dict):
                    cc = cobj.get("iso_code") or cobj.get("iso") or cobj.get("code") or cobj.get("country_code")
            except Exception:
                pass
            if not cc:
                cc = data.get("country_code") or data.get("country")
            country = (str(cc or "").strip().upper() or None)
            # Extract latitude/longitude
            lat = None
            lon = None
            try:
                loc = data.get("location") if isinstance(data, dict) else None
                if isinstance(loc, dict):
                    lat = loc.get("latitude") if loc.get("latitude") is not None else loc.get("lat")
                    lon = loc.get("longitude") if loc.get("longitude") is not None else loc.get("lon")
                if lat is None and isinstance(data, dict):
                    lat = data.get("latitude") or data.get("lat")
                if lon is None and isinstance(data, dict):
                    lon = data.get("longitude") or data.get("lon")
                lat = float(lat) if lat is not None else None
                lon = float(lon) if lon is not None else None
            except Exception as e:
                logger.debug("geo: _geo_from_ip geoapify parse lat/lon failed ip=%s err=%s", ip, e)
                lat, lon = None, None
            logger.debug("geo: _geo_from_ip (geoapify) ip=%s country=%s lat=%s lon=%s", ip, country, lat, lon)
            return country, lat, lon
        except Exception as e:
            logger.warning("geo: _geo_from_ip geoapify failed ip=%s err=%s", ip, e)
            # fallthrough
    # Fallback: DbIpCity when available
    if DbIpCity is not None:
        try:
            res = DbIpCity.get(ip, api_key="free")  # type: ignore
            country = (getattr(res, "country", None) or "").upper() or None
            lat = None
            lon = None
            try:
                lat = float(getattr(res, "latitude", None)) if getattr(res, "latitude", None) is not None else None
                lon = float(getattr(res, "longitude", None)) if getattr(res, "longitude", None) is not None else None
            except Exception as e:
                logger.debug("geo: _geo_from_ip dbipcity parse lat/lon failed ip=%s err=%s", ip, e)
                lat, lon = None, None
            logger.debug("geo: _geo_from_ip (dbipcity) ip=%s country=%s lat=%s lon=%s", ip, country, lat, lon)
            return country, lat, lon
        except Exception as e:
            logger.warning("geo: _geo_from_ip dbipcity failed ip=%s err=%s", ip, e)
    return None, None, None


# -----------------------------
# Routes
# -----------------------------

# Use the shared limiter instance configured in utils.limiter (supports both package and flat runs)
try:
    from ..utils.limiter import limiter  # type: ignore
except Exception:
    from utils.limiter import limiter  # type: ignore

router = APIRouter(prefix="/api/builder", tags=["builder"]) 

# Groq API key for AI Copilot (server-side only)
GROQ_API_KEY = os.getenv("GROQ_API_KEY") or os.getenv("GROQ_API_TOKEN") or ""

@router.post("/ai/copilot")
@limiter.limit("20/minute")
async def ai_copilot(request: Request, payload: Dict = None):
    """
    AI Form Copilot: generate form field suggestions, placeholders, and microcopy
    from a one-line prompt. Requires Firebase Authorization bearer token.

    Body: {
      prompt: string,
      language?: string (ISO),
      title?: string,
      industry?: string,
      currentFields?: [{ label, type, required?, placeholder? }],
      tone?: string (e.g., "professional", "friendly")
    }

    Returns: {
      success: true,
      suggestions: {
        title?: string,
        subtitle?: string,
        thankYouMessage?: string,
        fields: [ { id, label, type, required, placeholder?, maxLength? } ],
        notes?: string[]
      }
    }
    """
    uid = _verify_firebase_uid(request)
    if not isinstance(payload, dict):
        payload = {}

    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail="AI is not configured on server")

    user_prompt = (payload.get("prompt") or "").strip()
    if not user_prompt:
        raise HTTPException(status_code=400, detail="Missing prompt")

    language = (payload.get("language") or "en").strip()[:8]
    title = (payload.get("title") or "").strip()
    industry = (payload.get("industry") or "").strip()
    tone = (payload.get("tone") or "professional").strip()

    current_fields = []
    try:
        cf = payload.get("currentFields") or []
        if isinstance(cf, list):
            for f in cf:
                try:
                    current_fields.append({
                        "label": str((f or {}).get("label") or ""),
                        "type": str((f or {}).get("type") or ""),
                        "required": bool((f or {}).get("required", False)),
                        "placeholder": (str((f or {}).get("placeholder") or "").strip() or None),
                    })
                except Exception:
                    continue
    except Exception:
        current_fields = []

    # Constrain allowed types to server-supported set
    allowed_types = sorted(list(EXTENDED_ALLOWED_TYPES))

    system_prompt = (
        "You are an expert conversion-focused form builder assistant. "
        "Given a short prompt and optional context, produce a JSON object with: \n"
        "{\n  \"title\"?: string,\n  \"subtitle\"?: string,\n  \"thankYouMessage\"?: string,\n  \"fields\": [\n    { \"label\": string, \"type\": one of allowed types, \"required\": boolean, \"placeholder\"?: string, \"maxLength\"?: number }\n  ],\n  \"notes\"?: string[]\n}\n"
        "Rules: Use only these field types: " + ", ".join(allowed_types) + ". "
        "Prefer concise labels and helpful placeholders. Avoid personal/sensitive data. "
        "Limit to at most 10 fields. Make microcopy in language code: " + language + ". "
        "Tone should be: " + tone + ". "
    )

    # Compose user content
    user_content = {
        "prompt": user_prompt,
        "language": language,
        "title": title,
        "industry": industry,
        "currentFields": current_fields,
    }

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "CleanEnroll-Backend/1.0"
    }
    body = {
        "model": "llama-3.1-8b-instant",
        "temperature": 0.3,
        "max_tokens": 1200,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_content, ensure_ascii=False)}
        ]
    }

    try:
        r = requests.post(url, headers=headers, json=body, timeout=30)
        if not r.ok:
            raise HTTPException(status_code=502, detail=f"AI provider error: {r.status_code} {r.text[:200]}")
        data = r.json()
        content = ""
        try:
            content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        except Exception:
            content = ""
        if not content:
            raise HTTPException(status_code=502, detail="AI provider returned empty response")
        # Attempt to parse JSON; strip fences if present
        raw = content.strip()
        if raw.startswith("```"):
            m = re.search(r"```(?:json)?\n([\s\S]*?)\n```", raw)
            raw = (m.group(1) if m else raw)
        try:
            obj = json.loads(raw)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Failed to parse AI output: {e}")

        # Normalize and validate suggestions
        suggestions = {
            "title": (obj.get("title") or title or None),
            "subtitle": (obj.get("subtitle") or None),
            "thankYouMessage": (obj.get("thankYouMessage") or None),
            "fields": [],
            "notes": obj.get("notes") or [],
        }
        out_fields = []
        for f in (obj.get("fields") or [])[:10]:
            try:
                lab = str((f or {}).get("label") or "").strip()
                ftype = str((f or {}).get("type") or "").strip().lower()
                req = bool((f or {}).get("required", False))
                ph = (str((f or {}).get("placeholder") or "").strip() or None)
                maxlen = f.get("maxLength")
                if not lab:
                    continue
                if ftype not in EXTENDED_ALLOWED_TYPES:
                    ftype = "text"
                item = {"id": _create_id(), "label": lab, "type": ftype, "required": req}
                if ph:
                    item["placeholder"] = ph
                if isinstance(maxlen, int) and maxlen > 0:
                    item["maxLength"] = maxlen
                out_fields.append(item)
            except Exception:
                continue
        if not out_fields:
            # minimal fallback
            out_fields = [{"id": _create_id(), "label": "Your message", "type": "textarea", "required": True, "placeholder": "Tell us more..."}]
        suggestions["fields"] = out_fields

        return {"success": True, "suggestions": suggestions}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("ai_copilot failed uid=%s err=%s", uid, e)
        raise HTTPException(status_code=500, detail="AI suggestion failed") 


@router.post("/uploads/form-bg/presign")
async def presign_form_bg(request: Request, payload: Dict = None):
    """
    Generate a presigned PUT URL for uploading a form background image directly to Cloudflare R2.
    Requires Firebase Authorization bearer token.
    Body: { filename: string, contentType?: string }
    Returns: { uploadUrl, publicUrl, key, headers }
    """
    uid = _verify_firebase_uid(request)
    if not isinstance(payload, dict):
        payload = {}
    raw_name = str(payload.get("filename") or "background").strip() or "background"
    content_type = str(payload.get("contentType") or "image/jpeg").strip() or "image/jpeg"
    if not content_type.lower().startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image uploads are allowed")

    # Plan-based size validation (optional size provided by client)
    is_pro = _is_pro_plan(uid)
    try:
        size = int(payload.get("size") or 0)
    except Exception:
        size = 0
    limit = PRO_MAX_UPLOAD_BYTES if is_pro else FREE_MAX_UPLOAD_BYTES
    if size and size > limit:
        mb = int(limit // (1024 * 1024))
        raise HTTPException(status_code=413, detail=f"File too large. Maximum allowed is {mb}MB on your plan.")
    # Sanitize filename
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name)[:200] or "background.jpg"
    key = f"form-backgrounds/{uid}/{int(datetime.utcnow().timestamp()*1000)}_{safe_name}"
    try:
        s3 = _r2_client()
        params = {
            "Bucket": R2_BUCKET,
            "Key": key,
            "ContentType": content_type,
        }
        url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params=params,
            ExpiresIn=900,  # 15 minutes
        )
        public_url = _public_url_for_key(key)
        return {
            "uploadUrl": url,
            "publicUrl": public_url,
            "key": key,
            "headers": {"Content-Type": content_type},
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("R2 presign failed uid=%s", uid)
        raise HTTPException(status_code=500, detail=f"Failed to create upload URL: {e}") 

@router.post("/uploads/media/presign")
async def presign_field_media(request: Request, payload: Dict = None):
    """
    Generate a presigned PUT URL for uploading media for image/video/audio fields directly to Cloudflare R2.
    Requires Firebase Authorization bearer token.
    Body: { filename: string, contentType?: string, kind?: "image"|"video"|"audio", formId?: string, fieldId?: string }
    Returns: { uploadUrl, publicUrl, key, headers }
    """
    uid = _verify_firebase_uid(request)
    if not isinstance(payload, dict):
        payload = {}
    raw_name = str(payload.get("filename") or "media").strip() or "media"
    kind = str(payload.get("kind") or payload.get("type") or "image").strip().lower()
    if kind not in ("image", "video", "audio"):
        raise HTTPException(status_code=400, detail="kind must be one of image|video|audio")
    content_type = str(payload.get("contentType") or "").strip()
    if not content_type:
        content_type = {"image": "image/jpeg", "video": "video/mp4", "audio": "audio/mpeg"}[kind]
    if not content_type.lower().startswith(kind + "/"):
        raise HTTPException(status_code=400, detail=f"Content-Type must start with {kind}/")

    # Plan-based size validation (optional size provided by client)
    is_pro = _is_pro_plan(uid)
    try:
        size = int(payload.get("size") or 0)
    except Exception:
        size = 0
    limit = PRO_MAX_UPLOAD_BYTES if is_pro else FREE_MAX_UPLOAD_BYTES
    if size and size > limit:
        mb = int(limit // (1024 * 1024))
        raise HTTPException(status_code=413, detail=f"File too large. Maximum allowed is {mb}MB on your plan.")
    # Sanitize filename
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name)[:200] or f"{kind}"
    form_id = str(payload.get("formId") or "").strip()
    field_id = str(payload.get("fieldId") or "").strip()
    # Build key: form-media/<uid>/<kind>/<formId?>/<timestamp>_<filename>
    prefix = f"form-media/{uid}/{kind}/"
    if form_id:
        prefix += f"{form_id}/"
    key = f"{prefix}{int(datetime.utcnow().timestamp()*1000)}_{safe_name}"
    try:
        s3 = _r2_client()
        params = {
            "Bucket": R2_BUCKET,
            "Key": key,
            "ContentType": content_type,
        }
        url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params=params,
            ExpiresIn=900,  # 15 minutes
        )
        public_url = _public_url_for_key(key)
        return {
            "uploadUrl": url,
            "publicUrl": public_url,
            "key": key,
            "headers": {"Content-Type": content_type},
            "kind": kind,
            "formId": form_id or None,
            "fieldId": field_id or None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("R2 media presign failed uid=%s", uid)
        raise HTTPException(status_code=500, detail=f"Failed to create upload URL: {e}")

@router.post("/uploads/font/presign")
async def presign_font(request: Request, payload: Dict = None):
    """
    Generate a presigned PUT URL for uploading a custom font to Cloudflare R2.
    Supports TTF/OTF/WOFF/WOFF2. Requires Firebase Authorization bearer token.
    Body: { filename: string, contentType?: string, size?: number }
    Returns: { uploadUrl, publicUrl, key, headers, format }
    """
    uid = _verify_firebase_uid(request)
    if not isinstance(payload, dict):
        payload = {}
    raw_name = str(payload.get("filename") or "font").strip() or "font"

    # Detect content type and CSS format from file extension
    ext = os.path.splitext(raw_name)[1].lower()
    ext_map = {
        ".ttf": ("font/ttf", "truetype"),
        ".otf": ("font/otf", "opentype"),
        ".woff": ("font/woff", "woff"),
        ".woff2": ("font/woff2", "woff2"),
    }
    default_ct, fmt = ext_map.get(ext, ("application/octet-stream", None))
    content_type = str(payload.get("contentType") or default_ct).strip() or default_ct

    # Validate allowed content types
    allowed_cts = {
        "font/ttf", "font/otf", "font/woff", "font/woff2",
        "application/font-sfnt", "application/font-woff", "application/font-woff2",
        "application/octet-stream",
    }
    if (ext not in ext_map) and (content_type not in allowed_cts):
        raise HTTPException(status_code=400, detail="Unsupported font type. Allowed: TTF, OTF, WOFF, WOFF2")

    # Plan-based size validation (optional size provided by client)
    is_pro = _is_pro_plan(uid)
    try:
        size = int(payload.get("size") or 0)
    except Exception:
        size = 0
    limit = PRO_MAX_UPLOAD_BYTES if is_pro else FREE_MAX_UPLOAD_BYTES
    if size and size > limit:
        mb = int(limit // (1024 * 1024))
        raise HTTPException(status_code=413, detail=f"File too large. Maximum allowed is {mb}MB on your plan.")

    # Sanitize filename
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name)[:200] or ("font" + (ext if ext in ext_map else ".ttf"))
    key = f"fonts/{uid}/{int(datetime.utcnow().timestamp()*1000)}_{safe_name}"
    try:
        s3 = _r2_client()
        params = {
            "Bucket": R2_BUCKET,
            "Key": key,
            "ContentType": content_type,
        }
        url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params=params,
            ExpiresIn=900,  # 15 minutes
        )
        public_url = _public_url_for_key(key)
        # Determine CSS font format if not from extension
        if not fmt:
            cl = content_type.lower()
            if "woff2" in cl:
                fmt = "woff2"
            elif "woff" in cl:
                fmt = "woff"
            elif "otf" in cl or "opentype" in cl:
                fmt = "opentype"
            elif "ttf" in cl or "truetype" in cl:
                fmt = "truetype"
            else:
                fmt = "woff2"
        return {
            "uploadUrl": url,
            "publicUrl": public_url,
            "key": key,
            "headers": {"Content-Type": content_type},
            "format": fmt,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("R2 font presign failed uid=%s", uid)
        raise HTTPException(status_code=500, detail=f"Failed to create upload URL: {e}")

# Public presign for submission file uploads (no auth; rate-limited)
@router.post("/uploads/submissions/presign")
@limiter.limit("60/minute")
async def presign_submission_file(request: Request, payload: Dict = None):
    """
    Generate a presigned PUT URL for uploading a submission file to Cloudflare R2.
    Public endpoint (no auth) intended for end-users submitting forms.
    Body: { filename: string, contentType?: string, formId: string, size?: number }
    Returns: { uploadUrl, publicUrl, key, headers }
    """
    if not isinstance(payload, dict):
        payload = {}
    raw_name = str(payload.get("filename") or "file").strip() or "file"
    content_type = str(payload.get("contentType") or "application/octet-stream").strip() or "application/octet-stream"
    form_id = str(payload.get("formId") or "").strip()
    if not form_id:
        raise HTTPException(status_code=400, detail="formId is required")

    # Determine plan from form owner and enforce size limit (when size provided)
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    form_data = _read_json(path)
    owner_id = str(form_data.get("userId") or "").strip() or None
    is_pro = _is_pro_plan(owner_id)
    limit = PRO_MAX_UPLOAD_BYTES if is_pro else FREE_MAX_UPLOAD_BYTES
    try:
        size = int(payload.get("size") or 0)
    except Exception:
        size = 0
    if size and size > limit:
        mb = int(limit // (1024 * 1024))
        raise HTTPException(status_code=413, detail=f"File too large. Maximum allowed is {mb}MB on this form's plan.")
    # Sanitize filename
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name)[:200] or "file.bin"
    prefix = "submissions/uploads/"
    if form_id:
        prefix += f"{form_id}/"
    key = f"{prefix}{int(datetime.utcnow().timestamp()*1000)}_{safe_name}"
    try:
        s3 = _r2_client()
        params = {
            "Bucket": R2_BUCKET,
            "Key": key,
            "ContentType": content_type,
        }
        url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params=params,
            ExpiresIn=900,  # 15 minutes
        )
        public_url = _public_url_for_key(key)
        return {
            "uploadUrl": url,
            "publicUrl": public_url,
            "key": key,
            "headers": {"Content-Type": content_type},
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("R2 presign (submission) failed")
        raise HTTPException(status_code=500, detail=f"Failed to create upload URL: {e}")

@router.get("/uploads/attachment")
@limiter.limit("120/minute")
async def download_r2_attachment(request: Request, key: Optional[str] = None, url: Optional[str] = None, filename: Optional[str] = None):
    """
    Stream a file from Cloudflare R2 as an attachment.
    Provide either:
      - key: the R2 object key
      - url: a public R2 URL (we will extract the key from the path)
    Returns the file bytes with Content-Disposition: attachment.
    """
    try:
        resolved_key = (key or "").strip()
        if not resolved_key:
            u = (url or "").strip()
            if not u:
                raise HTTPException(status_code=400, detail="Provide 'key' or 'url'")
            try:
                pr = urlparse(u)
                # Example paths:
                #  - r2.dev: /<bucket>/<key>
                #  - r2.cloudflarestorage.com: /<bucket>/<key>
                path = (pr.path or "/").lstrip("/")
                parts = path.split("/", 1)
                if len(parts) >= 2:
                    # parts[0] is bucket, parts[1] is key
                    resolved_key = parts[1]
                else:
                    raise HTTPException(status_code=400, detail="Could not extract R2 key from url")
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid url")
        if not resolved_key:
            raise HTTPException(status_code=400, detail="Missing key")
        s3 = _r2_client()
        obj = s3.get_object(Bucket=R2_BUCKET, Key=resolved_key)
        body = obj.get("Body")
        if body is None:
            raise HTTPException(status_code=404, detail="File not found")
        content_type = obj.get("ContentType") or "application/octet-stream"
        # Derive filename
        fname = (filename or os.path.basename(resolved_key) or "file").strip()
        headers = {"Content-Disposition": f'attachment; filename="{fname}"'}
        try:
            clen = obj.get("ContentLength")
            if clen is not None:
                headers["Content-Length"] = str(int(clen))
        except Exception:
            pass
        return StreamingResponse(body, media_type=content_type, headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("attachment download failed key=%s", key or url)
        raise HTTPException(status_code=500, detail=f"Failed to fetch file: {e}")

@router.post("/forms/{form_id}/fields/{field_id}/media")
async def set_field_media(form_id: str, field_id: str, payload: Dict = None):
    """
    Set media URL (and optional poster) for an image/video/audio field on a form.
    Body: {
      key?: string,                 # R2 object key to derive public URL from
      url?: string | mediaUrl?: string,  # direct URL (will be normalized)
      posterKey?: string,           # optional R2 key for video poster
      posterUrl?: string | poster?: string,
    }
    Returns: { success: true, fieldId, mediaUrl, poster? }
    """
    if not isinstance(payload, dict):
        payload = {}
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    data = _read_json(path)
    fields = data.get("fields") or []
    idx = None
    for i, f in enumerate(fields):
        try:
            if str(f.get("id")) == str(field_id) or (str(f.get("label") or "").strip() == str(field_id)):
                idx = i
                break
        except Exception:
            continue
    if idx is None:
        raise HTTPException(status_code=404, detail="Field not found")
    fobj = fields[idx] or {}
    ftype = str(fobj.get("type") or "").strip().lower()
    if ftype not in ("image", "video", "audio"):
        raise HTTPException(status_code=400, detail="Field is not a media display type")

    # Resolve media URL
    key = str(payload.get("key") or payload.get("mediaKey") or "").strip()
    url = payload.get("mediaUrl") or payload.get("url")
    media_url: Optional[str] = None
    if key:
        media_url = _public_url_for_key(key)
    elif url:
        media_url = _normalize_bg_public_url(str(url))
    else:
        raise HTTPException(status_code=400, detail="Provide either key or mediaUrl/url")

    # Optional poster (for video primarily)
    poster_key = str(payload.get("posterKey") or "").strip()
    poster_url_in = payload.get("posterUrl") or payload.get("poster")
    poster_url: Optional[str] = None
    if poster_key:
        poster_url = _public_url_for_key(poster_key)
    elif poster_url_in:
        poster_url = _normalize_bg_public_url(str(poster_url_in))

    # Update field
    fobj["mediaUrl"] = media_url
    if poster_url is not None:
        fobj["poster"] = poster_url
    fields[idx] = fobj
    data["fields"] = fields
    data["updatedAt"] = datetime.utcnow().isoformat()
    _write_json(path, data)

    return {"success": True, "fieldId": field_id, "mediaUrl": media_url, **({"poster": poster_url} if poster_url is not None else {})}

# In-memory cache for world countries GeoJSON to reduce outbound fetches
_WORLD_COUNTRIES_CACHE: Dict[str, Any] = {"data": None, "ts": 0}

@router.get("/geo/world-countries")
async def get_world_countries():
    """Serve world countries GeoJSON (with ISO-2 'cca2') from server domain to comply with CSP.
    Tries jsDelivr, falls back to unpkg. Cached in-memory for 6h.
    """
    import time
    now = time.time()
    try:
        if _WORLD_COUNTRIES_CACHE.get("data") and (now - float(_WORLD_COUNTRIES_CACHE.get("ts") or 0) < 6 * 3600):
            return JSONResponse(content=_WORLD_COUNTRIES_CACHE["data"])  # type: ignore
    except Exception:
        pass
    sources = [
        "https://raw.githubusercontent.com/datasets/geo-countries/master/data/countries.geojson",
        "https://datahub.io/core/geo-countries/r/0.geojson",
    ]
    last_err = None
    for url in sources:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CleanEnroll/1.0 (+https://cleanenroll.com)"})
            with urllib.request.urlopen(req, timeout=10) as resp:  # type: ignore
                raw = resp.read().decode("utf-8")
                data = json.loads(raw)
                # Persist successful fetch to disk cache for offline fallback
                try:
                    _write_text(_WORLD_COUNTRIES_FILE, raw)
                except Exception:
                    pass
                _WORLD_COUNTRIES_CACHE["data"] = data
                _WORLD_COUNTRIES_CACHE["ts"] = now
                return JSONResponse(content=data)
        except Exception as e:
            last_err = e
            continue
    # Local fallback: serve from disk cache if available
    try:
        if os.path.exists(_WORLD_COUNTRIES_FILE):
            with open(_WORLD_COUNTRIES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            _WORLD_COUNTRIES_CACHE["data"] = data
            _WORLD_COUNTRIES_CACHE["ts"] = now
            return JSONResponse(content=data)
    except Exception:
        pass
    raise HTTPException(status_code=500, detail=f"Failed to load world countries: {last_err}") 

@router.get("/geo/search")
@limiter.limit("30/minute")
async def geo_search(request: Request, q: str, limit: int = 8, lang: str = "en"):
    """Proxy Nominatim search with proper headers to avoid 403 and comply with usage policy.
    Returns {items: [{label, lat, lon, importance, class, type}]}.
    """
    try:
        query = (q or "").strip()
        if len(query) < 3:
            raise HTTPException(status_code=400, detail="Query too short")
        try:
            lim = max(1, min(10, int(limit)))
        except Exception:
            lim = 8
        # Build URL and attach a descriptive User-Agent as per Nominatim usage policy
        url = (
            "https://nominatim.openstreetmap.org/search?format=jsonv2"
            + f"&q={urllib.parse.quote(query)}&addressdetails=1&limit={lim}&dedupe=1"
        )
        headers = {
            "User-Agent": "CleanEnroll/1.0 (+https://cleanenroll.com/contact)",
            "Accept-Language": (lang or "en")[:16],
        }
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:  # type: ignore
            raw = resp.read().decode("utf-8", errors="ignore")
        data = json.loads(raw)
        items = []
        if isinstance(data, list):
            for it in data:
                try:
                    items.append({
                        "label": it.get("display_name"),
                        "lat": it.get("lat"),
                        "lon": it.get("lon"),
                        "importance": it.get("importance"),
                        "class": it.get("class"),
                        "type": it.get("type"),
                    })
                except Exception:
                    continue
        return {"items": items[:lim]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("geo_search nominatim failed err=%s", e)
        raise HTTPException(status_code=502, detail="Location search failed")

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
    # Normalize background image URL and custom font to permanent public URLs if needed
    try:
        theme = data.get("theme") or {}
        raw_bg = theme.get("pageBackgroundImage")
        if raw_bg:
            theme["pageBackgroundImage"] = _normalize_bg_public_url(raw_bg)
        try:
            raw_font = theme.get("customFontUrl")
            if raw_font:
                theme["customFontUrl"] = _normalize_bg_public_url(raw_font)
        except Exception:
            pass
        data["theme"] = theme
    except Exception:
        pass

    # Normalize media field URLs to permanent public URLs (R2)
    try:
        fields = data.get("fields") or []
        for f in fields:
            try:
                ftype = str(f.get("type") or "").strip().lower()
            except Exception:
                ftype = ""
            if ftype in ("image", "video", "audio"):
                try:
                    if f.get("mediaUrl"):
                        f["mediaUrl"] = _normalize_bg_public_url(f.get("mediaUrl"))
                except Exception:
                    pass
                try:
                    if f.get("poster"):
                        f["poster"] = _normalize_bg_public_url(f.get("poster"))
                except Exception:
                    pass
        data["fields"] = fields
    except Exception:
        pass

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

    # Normalize background image URL and custom font to permanent public URLs if needed
    try:
        theme = data.get("theme") or {}
        raw_bg = theme.get("pageBackgroundImage")
        if raw_bg:
            theme["pageBackgroundImage"] = _normalize_bg_public_url(raw_bg)
        try:
            raw_font = theme.get("customFontUrl")
            if raw_font:
                theme["customFontUrl"] = _normalize_bg_public_url(raw_font)
        except Exception:
            pass
        data["theme"] = theme
    except Exception:
        pass

    # Normalize media field URLs to permanent public URLs (R2)
    try:
        fields = data.get("fields") or []
        for f in fields:
            try:
                ftype = str(f.get("type") or "").strip().lower()
            except Exception:
                ftype = ""
            if ftype in ("image", "video", "audio"):
                try:
                    if f.get("mediaUrl"):
                        f["mediaUrl"] = _normalize_bg_public_url(f.get("mediaUrl"))
                except Exception:
                    pass
                try:
                    if f.get("poster"):
                        f["poster"] = _normalize_bg_public_url(f.get("poster"))
                except Exception:
                    pass
        data["fields"] = fields
    except Exception:
        pass

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
        # Preserve stored responses directory by default to avoid accidental data loss.
        # Historical submissions remain available via /forms/{form_id}/responses even after form deletion.
        # If permanent purge is ever needed, do it via a dedicated admin operation.
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {e}")
    logger.info("form deleted id=%s (responses preserved)", form_id)
    return {"success": True, "responsesPreserved": True}


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
    logger.debug("geo_check ip=%s country=%s allowed=%s restricted=%s available=%s", ip, country, allowed, restricted, _GEO_LOOKUP_AVAILABLE)

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

    # Submission limit enforcement (file-backed count)
    try:
        limit_raw = form_data.get("submissionLimit")
        limit = int(limit_raw) if limit_raw is not None else 0
        if limit and limit > 0:
            dir_path = _responses_dir(form_id)
            current = 0
            if os.path.exists(dir_path):
                current = sum(1 for n in os.listdir(dir_path) if n.endswith('.json'))
            if current >= limit:
                raise HTTPException(status_code=429, detail="I'm sorry, we've reached the capacity limit, we cannot accept new submissions at this moment")
    except HTTPException:
        raise
    except Exception:
        # Fail open on unexpected errors
        pass

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

    # Enforce role-based email block (server-side) even if client validation is bypassed
    try:
        if is_pro and bool(form_data.get("blockRoleEmails")) and isinstance(payload, dict):
            fields_def = form_data.get("fields") or []
            bad_labels: List[str] = []  # type: ignore[name-defined]
            for f in fields_def:
                try:
                    ftype = str((f or {}).get("type") or "").strip().lower()
                    label = str((f or {}).get("label") or "Email").strip() or "Email"
                    fid = (f or {}).get("id")
                    # Heuristic: only check proper email fields or labels containing 'email'
                    is_email_field = (ftype == "email") or ("email" in label.lower())
                    if not is_email_field or not fid:
                        continue
                    v = payload.get(fid)
                    if not isinstance(v, str):
                        continue
                    val = v.strip()
                    if not val or "@" not in val:
                        continue
                    if _is_role_based_email(val):
                        bad_labels.append(label)
                except Exception:
                    continue
            if bad_labels:
                raise HTTPException(status_code=400, detail=f"Use a personal business email instead of a generic one for: {', '.join(sorted(set(bad_labels)))}")
    except HTTPException:
        raise
    except Exception:
        # Do not fail submission on unexpected server error here
        pass

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
            if (ftype == "email") or (ftype in ("text", "textarea") and "email" in label.lower()):
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

                # Reputation checks (optional)
                if bool(form_data.get("emailRejectBadReputation")):
                    try:
                        domain = (addr.split('@', 1)[1] or '').strip().lower()
                    except Exception:
                        domain = ''
                    if domain:
                        # Spamhaus listing -> reject
                        listed = _spamhaus_listed(domain)
                        if listed is True:
                            raise HTTPException(status_code=400, detail=f"The email domain for '{lab}' appears on a well-known blocklist. Please use a different email.")
                        # WHOIS domain age -> reject when very new
                        try:
                            min_days = int(form_data.get('minDomainAgeDays') or 30)
                        except Exception:
                            min_days = 30
                        age_days = _domain_age_days(domain)
                        if age_days is not None and age_days < max(1, min_days):
                            raise HTTPException(status_code=400, detail=f"The email domain for '{lab}' is very new ({age_days} days old). Please use a more established email domain.")
                        # SPF/DMARC/DKIM (reject when SPF and DMARC are both missing)
                        spf_ok = _has_spf(domain)
                        dmarc_ok = _has_dmarc(domain)
                        dkim_ok = _has_any_dkim(domain)
                        if (spf_ok is False and dmarc_ok is False):
                            raise HTTPException(status_code=400, detail=f"The email domain for '{lab}' lacks common anti-spoofing records (SPF/DMARC). Please use a more reputable email domain.")
                    # If no domain part, earlier validation will trigger errors
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
            # Normalize file inputs to public download URLs when possible
            try:
                ftype = str((f.get("type") or "")).strip().lower()
            except Exception:
                ftype = ""
            if ftype == "file" and val is not None:
                def _file_to_url(v):
                    try:
                        if isinstance(v, dict):
                            u = v.get("url") or v.get("publicUrl") or v.get("downloadUrl")
                            if u:
                                return _normalize_bg_public_url(str(u))
                            k = str(v.get("key") or v.get("r2Key") or "").strip()
                            if k:
                                return _public_url_for_key(k)
                            # Fallback to provided name/filename or stringified dict
                            return v.get("name") or v.get("filename") or str(v)
                        if isinstance(v, str):
                            s = v.strip()
                            if s.startswith("http://") or s.startswith("https://"):
                                return _normalize_bg_public_url(s)
                            return s
                        return str(v)
                    except Exception:
                        return str(v)
                if isinstance(val, list):
                    answers[fid] = [_file_to_url(x) for x in val]
                else:
                    answers[fid] = _file_to_url(val)
            elif val is not None:
                answers[fid] = val
        # Build a downloadable ZIP archive of uploaded files (best-effort)
        files_zip_meta = None
        try:
            file_entries = []  # list of tuples (fid, label, url)
            for f in fields_def:
                try:
                    if str((f.get("type") or "")).strip().lower() != "file":
                        continue
                    fid = str(f.get("id"))
                    label = str(f.get("label") or "")
                except Exception:
                    continue
                av = answers.get(fid)
                if isinstance(av, list):
                    for u in av:
                        if isinstance(u, str) and (u.startswith("http://") or u.startswith("https://")):
                            file_entries.append((fid, label, u))
                elif isinstance(av, str) and (av.startswith("http://") or av.startswith("https://")):
                    file_entries.append((fid, label, av))
            if file_entries:
                max_total_bytes = 200 * 1024 * 1024  # 200MB safety cap
                total = 0
                added = 0
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for idx, (fid, label, url) in enumerate(file_entries):
                        try:
                            r = requests.get(url, timeout=15)
                            if not r.ok:
                                continue
                            content = r.content or b""
                            total += len(content)
                            if total > max_total_bytes:
                                break
                            # Derive a sensible filename
                            try:
                                from urllib.parse import urlparse
                                bn = os.path.basename(urlparse(url).path) or f"file_{idx}"
                            except Exception:
                                bn = f"file_{idx}"
                            base_label = re.sub(r"[^a-zA-Z0-9_-]+", "-", (label or "").strip())[:60] or fid[:12]
                            arcname = f"{base_label}/{bn}"
                            zf.writestr(arcname, content)
                            added += 1
                        except Exception:
                            continue
                if added > 0:
                    data_bytes = buf.getvalue()
                    key = f"submissions/{form_id}/{response_id}_files.zip"
                    try:
                        s3 = _r2_client()
                        s3.put_object(Bucket=R2_BUCKET, Key=key, Body=data_bytes, ContentType="application/zip")
                        files_zip_meta = {"url": _public_url_for_key(key), "key": key, "count": added, "bytes": len(data_bytes)}
                    except Exception:
                        files_zip_meta = None
        except Exception:
            logger.exception("zip bundle failed form_id=%s", form_id)
        # Geo enrich from client IP
        country_code, lat, lon = _geo_from_ip(ip)
        logger.info("geo_enrich submit form_id=%s ip=%s country=%s lat=%s lon=%s", form_id, ip, country_code, lat, lon)
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
        if files_zip_meta:
            record["filesZip"] = files_zip_meta
        _write_json(_new_response_path(form_id, submitted_at, response_id), record)
        # Firestore counters: increment submissions and update lastSubmissionAt
        try:
            if _FS_AVAILABLE:
                try:
                    # Initialize Firebase Admin if needed
                    from firebase_admin import credentials as _fb_credentials  # type: ignore
                    if not getattr(firebase_admin, "_apps", None):
                        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or ""
                        try:
                            if cred_path and os.path.exists(cred_path):
                                cred = _fb_credentials.Certificate(cred_path)
                            else:
                                cred = _fb_credentials.ApplicationDefault()  # type: ignore
                            firebase_admin.initialize_app(cred)
                        except Exception:
                            # Best-effort; continue even if init fails
                            pass
                except Exception:
                    pass
                try:
                    fs = _fs.client()
                    ref = fs.collection("forms").document(form_id)
                    # Prefer atomic increment when available
                    try:
                        from google.cloud.firestore_v1 import Increment as _FSIncrement  # type: ignore
                        update_doc = {
                            "submissionsCount": _FSIncrement(1),
                            "submissions": _FSIncrement(1),
                            "lastSubmissionAt": _fs.SERVER_TIMESTAMP,
                        }
                        ref.set(update_doc, merge=True)
                    except Exception:
                        # Fallback: read-modify-write
                        snap = ref.get()
                        data_prev = snap.to_dict() or {}
                        prev = data_prev.get("submissionsCount")
                        if not isinstance(prev, int):
                            prev = data_prev.get("submissions") if isinstance(data_prev.get("submissions"), int) else 0
                        new_count = int(prev or 0) + 1
                        ref.set({
                            "submissionsCount": new_count,
                            "submissions": new_count,
                            "lastSubmissionAt": _fs.SERVER_TIMESTAMP,
                        }, merge=True)
                except Exception:
                    # Non-fatal if Firestore unavailable or misconfigured
                    pass
        except Exception:
            # Never fail the submission on analytics/counters failure
            pass
        # Update country analytics aggregation (file-based)
        try:
            if country_code:
                _analytics_increment_country(form_id, country_code, submitted_at)
        except Exception:
            logger.exception("analytics: country increment failed form_id=%s", form_id)
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
        # Attempt Slack notification if configured
        try:
            try:
                from .slack import try_notify_slack_for_form  # type: ignore
            except Exception:
                from routers.slack import try_notify_slack_for_form  # type: ignore
            owner_id = str(form_data.get("userId") or "").strip() or None
            if owner_id:
                try_notify_slack_for_form(owner_id, form_id, record)
        except Exception:
            logger.exception("slack notify failed form_id=%s", form_id)
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
    """
    Automatically issue and enable SSL for a verified custom domain.

    Flow:
    1. Ensure domain is verified (CNAME check passed).
    2. Run certbot to issue certificate (HTTP-01 with webroot or DNS-01 if configured).
    3. Write Nginx TLS server block for the domain.
    4. Reload Nginx.
    5. Fallback: mark domain as ready for Caddy on-demand TLS.
    """
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    data = _read_json(path)

    domain_val = (data.get("customDomain") or "").strip().lower()
    if not domain_val:
        raise HTTPException(status_code=400, detail="No custom domain configured")
    if not data.get("customDomainVerified"):
        raise HTTPException(status_code=400, detail="Domain not verified yet")

    certbot = CERTBOT_BIN
    logs: list[str] = []
    try:
        if certbot and shutil.which(certbot):
            os.makedirs(ACME_WEBROOT, exist_ok=True)
            use_dns = bool(CERTBOT_DNS_PROVIDER)

            dir_flags = (
                f" --config-dir {CERTBOT_CONFIG_DIR}"
                f" --work-dir {CERTBOT_WORK_DIR}"
                f" --logs-dir {CERTBOT_LOGS_DIR}"
            )

            if use_dns and str(CERTBOT_DNS_PROVIDER).lower() == "cloudflare" and CERTBOT_DNS_CREDENTIALS:
                # DNS-01 with Cloudflare
                cmd = (
                    f"{certbot} certonly --agree-tos --no-eff-email -n "
                    f"--email {EMAIL_FOR_LE} "
                    f"--dns-cloudflare --dns-cloudflare-credentials {CERTBOT_DNS_CREDENTIALS} "
                    f"--dns-cloudflare-propagation-seconds 60 "
                    f"-d {domain_val}" + dir_flags
                )
            else:
                # HTTP-01 with webroot
                cmd = (
                    f"{certbot} certonly --webroot -w {ACME_WEBROOT} "
                    f"--agree-tos --no-eff-email -n "
                    f"--email {EMAIL_FOR_LE} "
                    f"-d {domain_val}" + dir_flags
                )

            res = _shell(cmd)
            logs.append(res.stdout or "")
            if res.returncode != 0:
                raise HTTPException(status_code=502, detail=f"certbot failed: {(res.stdout or '')[-4000:]}")

            # Write Nginx TLS config dynamically
            if shutil.which(NGINX_BIN) and os.path.isdir(NGINX_SITES_AVAILABLE) and os.path.isdir(NGINX_SITES_ENABLED):
                site_path = os.path.join(NGINX_SITES_AVAILABLE, f"{domain_val}.conf")
                tls_conf = f"""
server {{
    listen 80;
    server_name {domain_val};

    location /.well-known/acme-challenge/ {{
        root {ACME_WEBROOT};
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    server_name {domain_val};

    ssl_certificate /etc/letsencrypt/live/{domain_val}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain_val}/privkey.pem;

    location / {{
        proxy_pass http://127.0.0.1:8000;  # adjust to your backend
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
                _write_text(site_path, tls_conf)

                # symlink into sites-enabled
                link_path = os.path.join(NGINX_SITES_ENABLED, f"{domain_val}.conf")
                _ensure_symlink(site_path, link_path)

                # test & reload
                reload_out = _nginx_test_and_reload()
                logs.append(reload_out)

            # Verify HTTPS works
            ssl_ok = False
            try:
                req = urllib.request.Request(url=f"https://{domain_val}", method="HEAD")
                with urllib.request.urlopen(req, timeout=8) as resp:
                    ssl_ok = 200 <= getattr(resp, 'status', 200) < 400
            except Exception:
                ssl_ok = False

            data["sslVerified"] = bool(ssl_ok)
            data["updatedAt"] = datetime.utcnow().isoformat()
            _write_json(path, data)

            return {
                "success": True,
                "domain": domain_val,
                "sslVerified": bool(ssl_ok),
                "mode": "certbot+nginx",
                "logs": ("\n".join(logs))[-8000:]
            }

    except HTTPException:
        raise
    except Exception as e:
        logs.append(f"certbot/nginx error: {e}")

    # Fallback: mark as ready for Caddy
    data["sslVerified"] = True
    data["updatedAt"] = datetime.utcnow().isoformat()
    _write_json(path, data)
    return {
        "success": True,
        "domain": domain_val,
        "sslVerified": True,
        "mode": "caddy",
        "message": "TLS will be issued automatically by Caddy on first HTTPS hit.",
        "logs": ("\n".join(logs))[-8000:]
    }


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

@router.get("/forms/{form_id}/analytics/countries")
async def get_countries_analytics(form_id: str, from_ts: Optional[str] = Query(default=None, alias="from"), to_ts: Optional[str] = Query(default=None, alias="to")):
    """
    Return aggregated submission counts by country for a form.
    Optional query params:
      - from (ISO datetime): include days >= this date
      - to (ISO datetime): include days <= this date
    When no range is provided, returns the all-time totals.
    """
    data = _load_analytics_countries(form_id)
    if not from_ts and not to_ts:
        return {"countries": data.get("total") or {}}

    def _to_date(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        try:
            x = str(s).strip()
            if x.endswith("Z"):
                x = x[:-1] + "+00:00"
            dt = datetime.fromisoformat(x)
            return dt
        except Exception:
            try:
                return datetime.fromisoformat(str(s)[:10] + "T00:00:00+00:00")
            except Exception:
                return None

    start = _to_date(from_ts)
    end = _to_date(to_ts)
    if start is None and end is None:
        return {"countries": data.get("total") or {}}

    daily = data.get("daily") or {}
    agg: Dict[str, int] = {}
    for day, bucket in daily.items():
        try:
            day_dt = datetime.fromisoformat(day + "T00:00:00+00:00")
        except Exception:
            continue
        if start and day_dt < start.replace(hour=0, minute=0, second=0, microsecond=0):
            continue
        if end and day_dt > end.replace(hour=0, minute=0, second=0, microsecond=0):
            continue
        for iso, cnt in (bucket or {}).items():
            try:
                agg[iso] = int(agg.get(iso, 0)) + int(cnt or 0)
            except Exception:
                continue
    return {"countries": agg}

# -----------------------------
# Supabase-backed: Analytics events, Notifications, Abandons
# -----------------------------

# Supabase configuration (REST/PostgREST)
SUPABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("SUPABASE_REST_URL") or ""
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY") or ""


def _sb_headers() -> Dict[str, str]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured on server")
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }


def _sb_get(table: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured on server")
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    try:
        resp = requests.get(url, headers=_sb_headers(), params=params, timeout=20)
        if resp.status_code == 404:
            # Table/view not found -> treat as empty
            return []
        if not resp.ok:
            raise HTTPException(status_code=502, detail=f"Supabase GET failed: {resp.text}")
        data = resp.json()
        return data if isinstance(data, list) else []
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Supabase error: {e}")


def _sb_upsert(table: str, row: Dict[str, Any], on_conflict: Optional[str] = None) -> Dict[str, Any]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured on server")
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    params = {}
    if on_conflict:
        params["on_conflict"] = on_conflict
    headers = _sb_headers()
    headers["Prefer"] = "resolution=merge-duplicates,return=representation"
    try:
        resp = requests.post(url, headers=headers, params=params, json=[row], timeout=20)
        if resp.status_code == 404:
            # Table not found
            raise HTTPException(status_code=404, detail=f"Supabase table '{table}' not found")
        if not resp.ok:
            raise HTTPException(status_code=502, detail=f"Supabase UPSERT failed: {resp.text}")
        try:
            arr = resp.json()
            return arr[0] if isinstance(arr, list) and arr else {}
        except Exception:
            return {}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Supabase error: {e}")


def _sb_update(table: str, match: Dict[str, str], row: Dict[str, Any]) -> int:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured on server")
    # Build filters like id=eq.123&user_id=eq.abc
    qp = "&".join([f"{k}=eq.{v}" for k, v in (match or {}).items()])
    url = f"{SUPABASE_URL}/rest/v1/{table}{('?'+qp) if qp else ''}"
    headers = _sb_headers()
    headers["Prefer"] = "return=representation"
    try:
        resp = requests.patch(url, headers=headers, json=row, timeout=20)
        if resp.status_code == 404:
            return 0
        if not resp.ok:
            raise HTTPException(status_code=502, detail=f"Supabase UPDATE failed: {resp.text}")
        try:
            arr = resp.json()
            return len(arr) if isinstance(arr, list) else 0
        except Exception:
            return 0
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Supabase error: {e}")


@router.post("/analytics/events")
async def ingest_analytics_event(payload: Dict = None, request: Request = None):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")
    # If Supabase not configured, accept no-op to avoid client errors
    if not (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY):
        return {"success": True}
    ev = payload.copy()
    now_iso = datetime.utcnow().isoformat()
    # Normalize fields
    ev_row = {
        "id": ev.get("id") or uuid.uuid4().hex,
        "form_id": ev.get("formId") or ev.get("form_id") or "",
        "user_id": ev.get("userId") or ev.get("user_id") or None,
        "type": (ev.get("type") or "").strip(),
        "ts": ev.get("ts") or now_iso,
        "device_type": ((ev.get("deviceInfo") or {}).get("deviceType") or ev.get("device_type") or None),
        "browser": ((ev.get("deviceInfo") or {}).get("browser") or ev.get("browser") or None),
        "os": ((ev.get("deviceInfo") or {}).get("os") or ev.get("os") or None),
        "session_id": ev.get("sessionId") or ev.get("session_id") or None,
        "visitor_id": ev.get("visitorId") or ev.get("visitor_id") or None,
        "field_id": ev.get("fieldId") or ev.get("field_id") or None,
        "field_label": ev.get("fieldLabel") or ev.get("field_label") or None,
        "duration_ms": ev.get("durationMs") or ev.get("duration_ms") or None,
        "fields_filled_count": ev.get("fieldsFilledCount") or ev.get("fields_filled_count") or None,
        "first_interaction_field_label": ev.get("firstInteractionFieldLabel") or ev.get("first_interaction_field_label") or None,
        "ip": None,
    }
    try:
        if request:
            ev_row["ip"] = _client_ip(request)
    except Exception:
        pass
    if not ev_row["form_id"] or not ev_row["type"]:
        raise HTTPException(status_code=400, detail="Missing formId or type")
    _sb_upsert("analytics_events", ev_row)
    return {"success": True, "id": ev_row["id"]}


@router.get("/analytics/forms/{form_id}/summary")
async def analytics_summary(form_id: str, from_ts: Optional[str] = Query(default=None, alias="from"), to_ts: Optional[str] = Query(default=None, alias="to")):
    if not (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY):
        # Minimal empty summary when Supabase not configured
        return {
            "totals": {"views": 0, "starts": 0, "submissions": 0, "focus": 0, "filled": 0, "errors": 0},
            "conversionRate": 0,
            "devices": {"mobile": 0, "desktop": 0, "unknown": 0},
            "browsers": {},
            "os": {},
            "fields": {"focus": {}, "errors": {}, "filled": {}},
            "daily": {},
        }
    # Fetch events (bounded range) and aggregate
    params: Dict[str, str] = {"select": "type,ts,device_type,browser,os,field_id,field_label,session_id,visitor_id", "form_id": f"eq.{form_id}", "order": "ts.asc"}
    if from_ts:
        params["ts"] = f"gte.{from_ts}"
    events = _sb_get("analytics_events", params)
    # Apply upper bound filter in Python
    if to_ts:
        try:
            to_dt = datetime.fromisoformat(to_ts.replace("Z","+00:00"))
            def _le(e):
                try:
                    s = str(e.get("ts") or "")
                    if s.endswith("Z"): s = s[:-1]+"+00:00"
                    dt = datetime.fromisoformat(s)
                    return dt <= to_dt
                except Exception:
                    return True
            events = [e for e in events if _le(e)]
        except Exception:
            pass
    totals = {"views": 0, "starts": 0, "submissions": 0, "focus": 0, "filled": 0, "errors": 0}
    devices = {"mobile": 0, "desktop": 0, "unknown": 0}
    browsers: Dict[str, int] = {}
    osb: Dict[str, int] = {}
    fields = {"focus": {}, "errors": {}, "filled": {}}
    daily: Dict[str, Dict[str, int]] = {}
    for e in events:
        t = (e.get("type") or "").lower()
        if t == "view": totals["views"] += 1
        elif t == "start": totals["starts"] += 1
        elif t == "submit": totals["submissions"] += 1
        elif t == "field_focus": totals["focus"] += 1
        elif t == "field_filled": totals["filled"] += 1
        elif t == "field_error": totals["errors"] += 1
        # day bucket
        try:
            s = str(e.get("ts") or "").strip()
            if s.endswith("Z"): s = s[:-1] + "+00:00"
            day = datetime.fromisoformat(s).date().isoformat()
            d = daily.get(day) or {"views":0,"starts":0,"submissions":0}
            if t == "view": d["views"] += 1
            if t == "start": d["starts"] += 1
            if t == "submit": d["submissions"] += 1
            daily[day] = d
        except Exception:
            pass
        # device
        dtp = (e.get("device_type") or "unknown").lower()
        devices[dtp] = devices.get(dtp, 0) + 1
        b = e.get("browser") or "Other"
        browsers[b] = browsers.get(b, 0) + 1
        o = e.get("os") or "Other"
        osb[o] = osb.get(o, 0) + 1
        # fields
        fid = e.get("field_id") or "unknown"
        flab = e.get("field_label") or fid
        if t == "field_focus":
            fields["focus"][flab] = fields["focus"].get(flab, 0) + 1
        if t == "field_filled":
            fields["filled"][flab] = fields["filled"].get(flab, 0) + 1
        if t == "field_error":
            fields["errors"][flab] = fields["errors"].get(flab, 0) + 1
    conv = round(((totals["submissions"] / totals["views"]) * 1000)) / 10 if totals["views"] else 0
    return {
        "totals": totals,
        "conversionRate": conv,
        "devices": devices,
        "browsers": browsers,
        "os": osb,
        "fields": fields,
        "daily": daily,
    }


@router.post("/abandons/upsert")
async def abandons_upsert(payload: Dict = None):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")
    if not (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY):
        return {"success": True}
    required = ["formId", "sessionId"]
    for k in required:
        if not payload.get(k):
            raise HTTPException(status_code=400, detail=f"Missing {k}")
    row = {
        "id": payload.get("sessionId"),
        "form_id": payload.get("formId"),
        "user_id": payload.get("userId") or None,
        "values": payload.get("values") or {},
        "filled_count": int(payload.get("filledCount") or 0),
        "total_fields": int(payload.get("totalFields") or 0),
        "progress": payload.get("progress") or None,
        "updated_at": datetime.utcnow().isoformat(),
        "last_activity_at": datetime.utcnow().isoformat(),
        "submitted": bool(payload.get("submitted")) if payload.get("submitted") is not None else False,
        "abandoned": bool(payload.get("abandoned")) if payload.get("abandoned") is not None else False,
        "submitted_at": payload.get("submittedAt") or None,
        "abandoned_at": payload.get("abandonedAt") or None,
        "step": int(payload.get("step") or 0) or None,
        "total_steps": int(payload.get("totalSteps") or 0) or None,
    }
    _sb_upsert("abandons", row, on_conflict="id")
    return {"success": True}


@router.get("/abandons/list")
async def abandons_list(formId: str, from_ts: Optional[str] = Query(default=None, alias="from"), to_ts: Optional[str] = Query(default=None, alias="to")):
    if not (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY):
        return {"items": []}
    rows = _sb_get("abandons", {"select": "id,form_id,values,filled_count,total_fields,progress,updated_at,last_activity_at,submitted,abandoned,submitted_at,abandoned_at,step,total_steps", "form_id": f"eq.{formId}", "order": "updated_at.desc"})
    # Optionally filter by from/to client-side
    return {"items": rows or []}


@router.get("/notifications")
async def notifications_list(userId: str):
    if not (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY):
        return {"items": []}
    rows = _sb_get("notifications", {"select": "id,form_id,form_title,preview,submitted_at,read,read_at", "user_id": f"eq.{userId}", "order": "submitted_at.desc"})
    return {"items": rows or []}


@router.post("/notifications/mark")
async def notifications_mark(payload: Dict = None):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")
    if not (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY):
        return {"updated": 0}
    nid = (payload.get("id") or "").strip()
    read = bool(payload.get("read", True))
    if not nid:
        raise HTTPException(status_code=400, detail="Missing id")
    cnt = _sb_update("notifications", {"id": nid}, {"read": read, "read_at": datetime.utcnow().isoformat()})
    return {"updated": cnt}

# -----------------------------
# DNS Provider: Cloudflare (API token based)
# -----------------------------

def _verify_firebase_uid(request: Request) -> str:
    try:
        from firebase_admin import auth as _admin_auth  # type: ignore
    except Exception:
        raise HTTPException(status_code=500, detail="Firebase Admin not available on server")
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authz or not authz.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization token")
    token = authz.split(" ", 1)[1].strip()
    try:
        decoded = _admin_auth.verify_id_token(token)
        uid = decoded.get("uid")
        if not uid:
            raise HTTPException(status_code=401, detail="Invalid token")
        return uid
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def _cf_api_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _store_cloudflare_token(uid: str, token: str) -> None:
    # Prefer Supabase storage
    if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
        try:
            row = {
                "uid": uid,
                "cloudflare_token": token,
                "updated_at": datetime.utcnow().isoformat(),
            }
            _sb_upsert("dns_integrations", row, on_conflict="uid")
            return
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to store DNS credentials (Supabase)")
    # Fallback to Firestore
    try:
        doc = _fs.client().collection("dns_integrations").document(uid)
        doc.set({
            "cloudflare": {
                "token": token,
                "updatedAt": datetime.utcnow().isoformat(),
            }
        }, merge=True)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to store DNS credentials")


def _get_cloudflare_token(uid: str) -> str:
    # Prefer Supabase
    if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
        try:
            rows = _sb_get("dns_integrations", {"select": "cloudflare_token,cloudflare", "uid": f"eq.{uid}", "limit": "1"})
            if rows:
                row = rows[0] or {}
                # Prefer flat column `cloudflare_token`, fallback to json column `cloudflare` {token}
                token = str((row.get("cloudflare_token") or (row.get("cloudflare") or {}).get("token") or "")).strip()
                if token:
                    return token
            raise HTTPException(status_code=400, detail="Cloudflare not connected for this account")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to load DNS credentials (Supabase)")
    # Fallback Firestore
    try:
        doc = _fs.client().collection("dns_integrations").document(uid).get()
        data = doc.to_dict() or {}
        token = ((data.get("cloudflare") or {}).get("token") or "").strip()
        if not token:
            raise HTTPException(status_code=400, detail="Cloudflare not connected for this account")
        return token
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to load DNS credentials")


def _write_cloudflare_credentials_file(token: str) -> str:
    # Write token in an ini file usable by certbot-dns-cloudflare plugin
    path = CERTBOT_DNS_CREDENTIALS or os.path.join(os.getcwd(), "data", "letsencrypt", "cloudflare.ini")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"dns_cloudflare_api_token = {token}\n")
        try:
            os.chmod(path, 0o600)  # best-effort on Unix
        except Exception:
            pass
        return path
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to write Cloudflare credentials file")


@router.post("/dns/cloudflare/connect")
async def cloudflare_connect(request: Request, payload: Dict = None):
    """
    Store Cloudflare API token for the current authenticated user.
    Body: { apiToken: string }
    """
    uid = _verify_firebase_uid(request)
    if not isinstance(payload, dict) or not str(payload.get("apiToken") or "").strip():
        raise HTTPException(status_code=400, detail="Missing apiToken")
    token = str(payload.get("apiToken")).strip()
    _store_cloudflare_token(uid, token)
    return {"success": True}


@router.get("/dns/cloudflare/zones")
async def cloudflare_list_zones(request: Request):
    """
    List Cloudflare zones for the connected account.
    """
    uid = _verify_firebase_uid(request)
    token = _get_cloudflare_token(uid)
    url = "https://api.cloudflare.com/client/v4/zones"
    try:
        resp = requests.get(url, headers=_cf_api_headers(token), timeout=15)
        data = resp.json()
        if not resp.ok:
            raise HTTPException(status_code=resp.status_code, detail=str(data))
        zones = []
        for z in (data.get("result") or []):
            try:
                zones.append({"id": z.get("id"), "name": z.get("name"), "status": z.get("status")})
            except Exception:
                continue
        return {"zones": zones}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cloudflare API error: {e}")


@router.post("/dns/cloudflare/zones/{zone_id}/records")
async def cloudflare_create_record(request: Request, zone_id: str, payload: Dict = None):
    """
    Create a DNS record in a Cloudflare zone.
    Body: { type: "CNAME"|"TXT"|..., name: string, content: string, ttl?: number, proxied?: bool }
    """
    uid = _verify_firebase_uid(request)
    token = _get_cloudflare_token(uid)
    body = payload or {}
    rtype = (body.get("type") or "").strip().upper()
    name = (body.get("name") or "").strip()
    content = (body.get("content") or "").strip()
    if not rtype or not name or not content:
        raise HTTPException(status_code=400, detail="Missing type/name/content")
    ttl = body.get("ttl") if isinstance(body.get("ttl"), int) else 120
    proxied = bool(body.get("proxied")) if rtype in ("A", "AAAA", "CNAME") else False
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    try:
        resp = requests.post(url, headers=_cf_api_headers(token), json={
            "type": rtype, "name": name, "content": content, "ttl": ttl, "proxied": proxied
        }, timeout=20)
        data = resp.json()
        if not resp.ok or not data.get("success"):
            raise HTTPException(status_code=resp.status_code, detail=str(data))
        return {"success": True, "record": data.get("result")}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cloudflare API error: {e}")


@router.post("/dns/cloudflare/connect-domain")
async def cloudflare_connect_domain(request: Request, payload: Dict = None):
    """
    Automatically connect a custom domain for a form using Cloudflare:
      Body: { formId: string, zoneId: string, subdomain: string }
      - Creates CNAME record: subdomain.zone -> CUSTOM_DOMAIN_TARGET
      - Verifies domain in builder store
      - Writes Cloudflare credentials ini for DNS-01
      - Issues certificate (DNS-01) or falls back to on-demand TLS
    """
    uid = _verify_firebase_uid(request)
    body = payload or {}
    form_id = (body.get("formId") or "").strip()
    zone_id = (body.get("zoneId") or "").strip()
    sub = (body.get("subdomain") or "").strip().strip(".")
    if not form_id or not zone_id or not sub:
        raise HTTPException(status_code=400, detail="Missing formId/zoneId/subdomain")

    # Ensure token present
    token = _get_cloudflare_token(uid)

    # Fetch zone to get apex domain
    try:
        zurl = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
        zres = requests.get(zurl, headers=_cf_api_headers(token), timeout=15)
        zdata = zres.json()
        if not zres.ok or not zdata.get("success"):
            raise HTTPException(status_code=zres.status_code, detail=str(zdata))
        apex = (zdata.get("result") or {}).get("name") or ""
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cloudflare API error: {e}")

    full_domain = f"{sub}.{apex}" if apex else sub

    # Create/Upsert CNAME record (idempotent best-effort)
    try:
        # Try to find existing record
        list_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        qparams = {"type": "CNAME", "name": full_domain}
        lres = requests.get(list_url, headers=_cf_api_headers(token), params=qparams, timeout=15)
        existing_id = None
        if lres.ok:
            ldata = lres.json()
            for r in (ldata.get("result") or []):
                if str(r.get("name")).lower() == full_domain.lower():
                    existing_id = r.get("id")
                    break
        target = CUSTOM_DOMAIN_TARGET
        if existing_id:
            ures = requests.put(f"{list_url}/{existing_id}", headers=_cf_api_headers(token), json={
                "type": "CNAME", "name": full_domain, "content": target, "ttl": 120, "proxied": False
            }, timeout=20)
            if not ures.ok or not (ures.json() or {}).get("success"):
                raise HTTPException(status_code=ures.status_code, detail=str(ures.text))
        else:
            cres = requests.post(list_url, headers=_cf_api_headers(token), json={
                "type": "CNAME", "name": full_domain, "content": target, "ttl": 120, "proxied": False
            }, timeout=20)
            if not cres.ok or not (cres.json() or {}).get("success"):
                raise HTTPException(status_code=cres.status_code, detail=str(cres.text))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cloudflare API error: {e}")

    # Verify domain in our builder store
    try:
        await verify_custom_domain(form_id, payload={"customDomain": full_domain})
    except HTTPException as e:
        # Not fatal; continue to cert issuance
        logger.warning("verify_custom_domain failed: %s", e.detail)
    except Exception:
        logger.exception("verify_custom_domain failed")

    # Prepare credentials for DNS-01 and issue cert
    try:
        cred_path = _write_cloudflare_credentials_file(token)
        os.environ["CERTBOT_DNS_PROVIDER"] = "cloudflare"
        os.environ["CERTBOT_DNS_CREDENTIALS"] = cred_path
        result = await issue_cert(form_id)  # type: ignore
    except HTTPException as e:
        # Fall back to ready state (Caddy on-demand)
        logger.warning("issue_cert failed: %s", e.detail)
        result = {"success": True, "domain": full_domain, "mode": "fallback"}
    except Exception as e:
        logger.exception("issue_cert error")
        result = {"success": True, "domain": full_domain, "mode": "fallback"}

    return {"connected": True, "domain": full_domain, "details": result}
