from fastapi import APIRouter, HTTPException, Query, Request, Response, UploadFile, File
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
import shlex
import requests
import zipfile
import io
import boto3
from botocore.client import Config as BotoConfig
import socket
import threading
import time
from sqlalchemy import text, bindparam
from sqlalchemy.types import Integer
# Optional URL shortener
try:
    import pyshorteners  # type: ignore
    _PYSHORT_AVAILABLE = True
except Exception:
    pyshorteners = None  # type: ignore
    _PYSHORT_AVAILABLE = False

# File redirect utilities for short links
try:
    from routers.file_redirects import create_file_redirect, get_short_url  # type: ignore
    _FILE_REDIRECTS_AVAILABLE = True
except Exception:
    _FILE_REDIRECTS_AVAILABLE = False  # type: ignore
    _PYSHORT_AVAILABLE = False

# Owner email notifications
from routers.owner_notifications import get_owner_email, send_owner_notification

# Client email notifications (auto-reply/thank you emails)
from routers.client_notifications import send_auto_reply_email

# Geo restrictions (country allow/block)
from routers.geo_restrictions import _normalize_country_list, _client_ip, _country_from_ip

# Email integrations: encryption and sending
from cryptography.fernet import Fernet
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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
    from utils.email import render_email, send_email_html  # type: ignore
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
IPINFO_API_TOKEN = os.getenv("IPINFO_API_TOKEN") or ""
_GEOAPIFY_AVAILABLE = bool(GEOAPIFY_API_KEY)
_IPINFO_AVAILABLE = bool(IPINFO_API_TOKEN)
_GEO_LOOKUP_AVAILABLE = bool(_IPINFO_AVAILABLE or _GEOAPIFY_AVAILABLE or _DBIPCITY_AVAILABLE)

# Firestore (optional for legacy mirroring)
try:
    from utils import firestore as _fs  # type: ignore
    _FS_AVAILABLE = True
except Exception:
    _fs = None  # type: ignore
    _FS_AVAILABLE = False

# Logger
logger = logging.getLogger("backend.builder")
# Log geo lookup availability at import time
try:
    logger.info("geo: providers ipinfo=%s geoapify=%s dbipcity=%s", _IPINFO_AVAILABLE, _GEOAPIFY_AVAILABLE, _DBIPCITY_AVAILABLE)
    if not _GEO_LOOKUP_AVAILABLE:
        logger.warning("geo: no geolocation provider available; country/lat/lon enrichment disabled")
except Exception:
    pass

from typing import Optional as _Optional

# Shared limiter and async DB session must be defined before any route decorators
try:
    from slowapi import Limiter
    from utils.limiter import forwarded_for_ip
    from utils.encryption import decrypt_submission_data  # type: ignore
    from db.database import async_session_maker  # type: ignore
    limiter = Limiter(key_func=forwarded_for_ip)
except Exception:
    from utils.limiter import limiter  # type: ignore
    from db.database import async_session_maker  # type: ignore

# FastAPI router for this module
router = APIRouter(prefix="/api/builder", tags=["builder"])

async def _is_pro_plan(user_id: _Optional[str]) -> bool:
    """Return True if the user's plan in Neon is a paid tier."""
    if not user_id:
        return False
    try:
        async with async_session_maker() as session:  # type: ignore
            res = await session.execute(
                text("SELECT plan FROM users WHERE uid = :uid OR id = :uid LIMIT 1"),
                {"uid": user_id},
            )
            row = res.mappings().first()
            plan = str((row or {}).get("plan") or "").lower()
            return plan in ("pro", "business", "enterprise")
    except Exception:
        return False


# Storage
BACKING_DIR = os.path.join(os.getcwd(), "data", "forms")
os.makedirs(BACKING_DIR, exist_ok=True)

FREE_MONTHLY_SUBMISSION_LIMIT = 50


# Plan-based upload limits
FREE_MAX_UPLOAD_BYTES = 50 * 1024 * 1024      # 50MB for Free plan
PRO_MAX_UPLOAD_BYTES = 1024 * 1024 * 1024     # 1GB for Pro/paid plans

# Cloudflare R2 configuration (S3-compatible)
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID") or os.getenv("CLOUDFLARE_R2_ACCOUNT_ID") or ""
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID") or os.getenv("CLOUDFLARE_R2_ACCESS_KEY_ID") or ""
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY") or os.getenv("CLOUDFLARE_R2_SECRET_ACCESS_KEY") or ""
R2_BUCKET = os.getenv("R2_BUCKET") or "formbg"
R2_PUBLIC_BASE = os.getenv("R2_PUBLIC_BASE") or os.getenv("R2_PUBLIC_DOMAIN") or "https://pub-e30045e3902945f4ada02414d0573c3b.r2.dev"

# Best-effort URL shortener with timeout, falls back to original on failure
def _shorten_url(u: str) -> str:
    try:
        s = str(u or "").strip()
        if not s or not s.startswith(("http://", "https://")):
            return s
        if not _PYSHORT_AVAILABLE:
            return s
        try:
            shortener = pyshorteners.Shortener(timeout=6)
            short = shortener.tinyurl.short(s)
            return str(short or s)
        except Exception:
            return s
    except Exception:
        return u




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

 


async def _analytics_increment_country(session, form_id: str, country_iso2: Optional[str], submitted_at) -> None:
    """Increment Neon-backed per-day country counters.
    Uses INSERT ... ON CONFLICT to atomically increment the counter.
    """
    if not country_iso2:
        return
    try:
        iso = str(country_iso2 or "").strip().upper()
        if not iso:
            return
        # Derive day (UTC) from submitted_at (can be datetime or string)
        if isinstance(submitted_at, datetime):
            day_obj = submitted_at.date()
        else:
            s = str(submitted_at or "").strip()
            try:
                if s.endswith("Z"):
                    s = s[:-1] + "+00:00"
                dt = datetime.fromisoformat(s)
                day_obj = dt.date()
            except Exception:
                day_obj = datetime.utcnow().date()
        await session.execute(
            text(
                """
                INSERT INTO form_countries_analytics (form_id, day, country_iso2, count)
                VALUES (:fid, :day, :iso, 1)
                ON CONFLICT (form_id, day, country_iso2)
                DO UPDATE SET count = form_countries_analytics.count + 1
                """
            ),
            {"fid": form_id, "day": day_obj, "iso": iso},
        )
    except Exception:
        logger.exception("analytics countries increment error form_id=%s", form_id)

# Geo data local cache directory and file
WORLD_GEO_DIR = os.path.join(os.getcwd(), "data", "geo")
os.makedirs(WORLD_GEO_DIR, exist_ok=True)
_WORLD_COUNTRIES_FILE = os.path.join(WORLD_GEO_DIR, "world-countries.geo.json")


def _form_path(form_id: str) -> str:
    # Sanitize form_id and ensure the resulting file stays within BACKING_DIR
    safe_id = re.sub(r"[^a-zA-Z0-9._-]", "_", str(form_id or ""))
    base = os.path.abspath(BACKING_DIR)
    path = os.path.normpath(os.path.join(BACKING_DIR, f"{safe_id}.json"))
    if os.path.commonpath([base, os.path.abspath(path)]) != base:
        raise HTTPException(status_code=400, detail="Invalid form id")
    return path



def _write_json(path: str, data: Dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _read_json(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Temporary stubs for countries analytics storage (migrated away from filesystem)
def _load_analytics_countries(form_id: str) -> Dict[str, Any]:
    """Return countries analytics structure for a form.
    Structure: { "total": {ISO2: count}, "daily": {YYYY-MM-DD: {ISO2: count}}, "updatedAt": iso }
    Currently returns an empty structure as a safe default. Neon-backed implementation TODO.
    """
    try:
        return {"total": {}, "daily": {}, "updatedAt": datetime.utcnow().isoformat()}
    except Exception:
        return {"total": {}, "daily": {}}


def _save_analytics_countries(form_id: str, data: Dict[str, Any]) -> None:
    """Persist countries analytics. No-op placeholder while migrating to Neon."""
    try:
        return None
    except Exception:
        return None

async def _ensure_form_analytics_table(session):
    try:
        await session.execute(text(
            """
            CREATE TABLE IF NOT EXISTS form_analytics_events (
                id TEXT PRIMARY KEY,
                form_id TEXT NOT NULL,
                user_id TEXT,
                type TEXT NOT NULL,
                ts TIMESTAMPTZ,
                session_id TEXT,
                visitor_id TEXT,
                device_info JSONB,
                data JSONB,
                ip TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """
        ))
        await session.execute(text(
            """
            CREATE INDEX IF NOT EXISTS idx_form_analytics_form_ts ON form_analytics_events(form_id, ts);
            """
        ))
    except Exception:
        pass

@router.post("/analytics/events")
@limiter.limit("600/minute")
async def analytics_events(request: Request, payload: Dict[str, Any] | None = None):
    """Accept client analytics events from the viewer page. Best-effort persist; never error fatally."""
    try:
        body = payload or {}
    except Exception:
        body = {}

    # Normalize fields expected from analyticsService.js
    eid = str(body.get("id") or uuid.uuid4().hex)
    form_id = str(body.get("formId") or "").strip()
    if not form_id:
        # Ignore events without a form id
        return {"ok": False}
    etype = str(body.get("type") or "").strip() or "event"
    ts_raw = str(body.get("ts") or "").strip()
    try:
        ts = None
        if ts_raw:
            if ts_raw.endswith("Z"):
                ts_raw = ts_raw[:-1] + "+00:00"
            ts = datetime.fromisoformat(ts_raw)
    except Exception:
        ts = None
    session_id = body.get("sessionId") or None
    visitor_id = body.get("visitorId") or None
    device_info = body.get("deviceInfo") if isinstance(body.get("deviceInfo"), dict) else None
    # Keep the rest as generic data
    extras_keys = {"id","formId","userId","type","ts","deviceInfo","sessionId","visitorId"}
    data = {k: v for k, v in body.items() if k not in extras_keys}
    ip = _client_ip(request)

    try:
        async with async_session_maker() as session:
            await _ensure_form_analytics_table(session)
            
            # Prepare common params
            event_ts = ts or datetime.utcnow()
            device_info_json = json.dumps(device_info) if isinstance(device_info, dict) else None
            data_json = json.dumps(data) if isinstance(data, dict) else json.dumps({})
            
            # Insert into form_analytics_events (original table)
            await session.execute(
                text(
                    """
                    INSERT INTO form_analytics_events (id, form_id, user_id, type, ts, session_id, visitor_id, device_info, data, ip)
                    VALUES (:id, :form_id, :user_id, :type, :ts, :session_id, :visitor_id, CAST(:device_info AS JSONB), CAST(:data AS JSONB), :ip)
                    ON CONFLICT (id) DO NOTHING
                    """
                ),
                {
                    "id": eid,
                    "form_id": form_id,
                    "user_id": body.get("userId") or None,
                    "type": etype,
                    "ts": event_ts,
                    "session_id": session_id,
                    "visitor_id": visitor_id,
                    "device_info": device_info_json,
                    "data": data_json,
                    "ip": ip,
                }
            )
            
            # Also insert into unified analytics table with all metrics
            await session.execute(
                text(
                    """
                    INSERT INTO analytics (id, form_id, user_id, type, ts, session_id, visitor_id, device_info, data, ip_address, created_at)
                    VALUES (:id, :form_id, :user_id, :type, :ts, :session_id, :visitor_id, CAST(:device_info AS JSONB), CAST(:data AS JSONB), :ip, NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        session_id = EXCLUDED.session_id,
                        visitor_id = EXCLUDED.visitor_id,
                        device_info = EXCLUDED.device_info,
                        data = EXCLUDED.data,
                        ts = EXCLUDED.ts,
                        ip_address = EXCLUDED.ip_address
                    """
                ),
                {
                    "id": eid,
                    "form_id": form_id,
                    "user_id": body.get("userId") or None,
                    "type": etype,
                    "ts": event_ts,
                    "session_id": session_id,
                    "visitor_id": visitor_id,
                    "device_info": device_info_json,
                    "data": data_json,
                    "ip": ip,
                }
            )
            
            await session.commit()
    except Exception:
        # Best effort only
        pass
    return {"ok": True}

@router.get("/brand/colors")
@limiter.limit("30/minute")
async def get_brand_colors(request: Request, url: str = Query(...)):
    """Extract brand colors from a website URL using Selenium screenshots and ColorThief."""
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from webdriver_manager.chrome import ChromeDriverManager
    from colorthief import ColorThief
    from PIL import Image
    import tempfile
    
    driver = None
    try:
        if not url or not url.strip():
            raise HTTPException(status_code=400, detail="URL is required")
        
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        # Set up headless Chrome
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        
        # Initialize driver with webdriver-manager
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(15)
        
        # Navigate to the website
        logger.info(f"Taking screenshots of {url}")
        driver.get(url)
        
        # Wait for page to load
        import time
        time.sleep(2)  # Give time for dynamic content to render
        
        all_colors = []
        
        # Take screenshots at different scroll positions to capture more of the page
        scroll_positions = [0, 500, 1000]  # Top, middle-ish, lower sections
        
        for scroll_y in scroll_positions:
            try:
                # Scroll to position
                driver.execute_script(f"window.scrollTo(0, {scroll_y});")
                time.sleep(0.5)  # Brief pause for scroll to complete
                
                # Take screenshot to temporary file
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_file:
                    screenshot_path = tmp_file.name
                    driver.save_screenshot(screenshot_path)
                    
                    # Extract colors using ColorThief
                    try:
                        color_thief = ColorThief(screenshot_path)
                        
                        # Get dominant color
                        try:
                            dominant_color = color_thief.get_color(quality=1)
                            hex_color = f"#{dominant_color[0]:02x}{dominant_color[1]:02x}{dominant_color[2]:02x}"
                            all_colors.append(hex_color)
                        except Exception:
                            pass
                        
                        # Get color palette (up to 8 colors per screenshot)
                        try:
                            color_palette = color_thief.get_palette(color_count=8, quality=1)
                            for rgb in color_palette:
                                hex_color = f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
                                all_colors.append(hex_color)
                        except Exception:
                            pass
                    except Exception as e:
                        logger.debug(f"Failed to extract colors from screenshot at position {scroll_y}: {e}")
                    finally:
                        # Clean up temporary file
                        try:
                            os.unlink(screenshot_path)
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"Failed to capture screenshot at scroll position {scroll_y}: {e}")
                continue
        
        # Filter out near-white and near-black colors
        filtered_colors = []
        for color in all_colors:
            try:
                hex_val = color.replace('#', '')
                if len(hex_val) == 6:
                    r = int(hex_val[0:2], 16)
                    g = int(hex_val[2:4], 16)
                    b = int(hex_val[4:6], 16)
                    brightness = (r * 299 + g * 587 + b * 114) / 1000
                    # Skip very light (>240) or very dark (<20) colors
                    if 20 < brightness < 240:
                        filtered_colors.append(color)
            except Exception:
                pass
        
        # Remove duplicates while preserving order
        seen = set()
        palette = []
        for color in filtered_colors:
            color_lower = color.lower()
            if color_lower not in seen:
                seen.add(color_lower)
                palette.append(color)
                if len(palette) >= 8:
                    break
        
        # If we have colors, return them with a primary suggestion
        if palette:
            return {
                "palette": palette,
                "colors": {"primary": palette[0]},
                "suggestions": {
                    "theme": {"primaryColor": palette[0]}
                }
            }
        else:
            # Fallback: return default palette
            return {
                "palette": ["#3b82f6", "#8b5cf6", "#ec4899", "#f59e0b"],
                "colors": {"primary": "#3b82f6"},
                "suggestions": {"theme": {"primaryColor": "#3b82f6"}}
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Brand colors extraction failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to extract colors")
    finally:
        # Always close the browser
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

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
    subtitleColor: str = "#6b7280"
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
    # Split image mode
    splitImageEnabled: bool = False
    thankYouBgColor: str = "#ecfdf5"
    thankYouTextColor: str = "#065f46"
    # Font settings (persist custom or Google font)
    fontFamily: Optional[str] = "Inter"
    fontUrl: Optional[str] = None
    customFontUrl: Optional[str] = None
    customFontName: Optional[str] = None
    customFontFormat: Optional[str] = None
    # Form container shape and split-view options
    formShape: Literal["rectangle", "rounded", "pill", "circle", "heart", "blob", "hexagon"] = "rectangle"
    splitImageUrl: Optional[str] = None
    splitImagePosition: Literal["left", "right"] = "right"
    splitImageFit: Literal["cover", "contain"] = "cover"
    splitImageWidthPercent: int = Field(default=50, ge=20, le=80)
    splitImageBgColor: Optional[str] = None
    # Submit button styling (label/color/textColor)
    submitButton: SubmitButton = Field(default_factory=SubmitButton)
    # Typography styles under theme (mirror of top-level fields)
    titleStyle: Dict[str, Any] = Field(default_factory=dict)
    subtitleStyle: Dict[str, Any] = Field(default_factory=dict)


class HeadingStyle(BaseModel):
    bold: bool = False
    italic: bool = False
    level: Literal[1,2,3,4,5,6] = 1


class RedirectConfig(BaseModel):
    enabled: bool = False
    url: Optional[str] = None


class FieldSchema(BaseModel):
    # Common core props
    id: Optional[str] = None
    label: str = "Untitled"
    type: str = "text"
    required: bool = False
    placeholder: Optional[str] = None

    # Choice fields
    options: Optional[List[str]] = None
    maxSelections: Optional[int] = None

    # Step (for multi-step forms)
    step: Optional[int] = None

    # Text constraints
    maxLength: Optional[int] = None

    # File upload constraints
    accept: Optional[str] = None
    multiple: Optional[bool] = None

    # Phone input
    phoneAllowedCountry: Optional[str] = None

    # Price input
    currency: Optional[str] = None
    minPrice: Optional[float] = None
    maxPrice: Optional[float] = None

    # Rating inputs
    max: Optional[int] = None
    emojiLabels: Optional[List[str]] = None

    # Linear scale
    minScale: Optional[int] = None
    maxScale: Optional[int] = None
    lowLabel: Optional[str] = None
    highLabel: Optional[str] = None

    # Password config
    passwordMinLength: Optional[int] = None
    passwordRequireUppercase: Optional[bool] = None
    passwordRequireLowercase: Optional[bool] = None
    passwordRequireNumber: Optional[bool] = None
    passwordRequireSpecial: Optional[bool] = None

    # Full-name config
    fullNameRequireTwoWords: Optional[bool] = None
    fullNameDisplayMode: Optional[str] = None  # 'single' | 'split'
    firstNameLabel: Optional[str] = None
    lastNameLabel: Optional[str] = None
    firstNamePlaceholder: Optional[str] = None
    lastNamePlaceholder: Optional[str] = None

    # Media display (non-interactive)
    mediaUrl: Optional[str] = None
    caption: Optional[str] = None

class FormConfig(BaseModel):
    id: Optional[str] = None
    userId: Optional[str] = None
    title: str = "Untitled Form"
    subtitle: str = ""
    # Title/subtitle typography
    titleStyle: Optional[HeadingStyle] = HeadingStyle(bold=True, italic=False, level=1)
    subtitleStyle: Optional[HeadingStyle] = HeadingStyle(bold=False, italic=False, level=3)
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
    urlScanEnabled: bool = False
    gdprComplianceEnabled: bool = False
    showPoweredBy: bool = True
    passwordProtectionEnabled: bool = False
    passwordHash: Optional[str] = None
    preventDuplicateByUID: bool = False
    isPublished: bool = False
    submitButton: SubmitButton = SubmitButton()
    formType: Literal["simple", "multi-step"] = "simple"
    # Layout variant controls overall page composition
    layoutVariant: Literal["card", "split"] = "card"
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
    # Domains allowed to embed this form (origins/domains)
    embedAllowList: Optional[List[str]] = []
    # Auto-reply email to client after submission
    autoReplyEnabled: bool = False
    autoReplyEmailFieldId: Optional[str] = None
    autoReplySubject: Optional[str] = None
    autoReplyMessageHtml: Optional[str] = None
    # Optional custom footer HTML for auto-reply emails
    autoReplyFooterHtml: Optional[str] = None
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
    # New input types
    "time",
    "count",
    "linear-scale",
    "range-slider",
    # Media display (non-interactive)
    "image",
    "video",
    "audio",
    "signature",
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

        # Time field validation
        if f.type == "time":
            def _is_time_str(s: Optional[str]) -> bool:
                try:
                    if s is None:
                        return True
                    ss = str(s).strip()
                    return bool(re.match(r"^\d{2}:\d{2}(:\d{2})?$", ss))
                except Exception:
                    return False
            if not _is_time_str(getattr(f, "minTime", None)):
                raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid minTime (use HH:MM or HH:MM:SS)")
            if not _is_time_str(getattr(f, "maxTime", None)):
                raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid maxTime (use HH:MM or HH:MM:SS)")
            # Compare times when both provided
            def _to_secs(s: str) -> int:
                parts = [int(p) for p in s.split(":")]
                if len(parts) == 2:
                    h, m = parts
                    sec = 0
                else:
                    h, m, sec = parts
                return max(0, h) * 3600 + max(0, m) * 60 + max(0, sec)
            if getattr(f, "minTime", None) and getattr(f, "maxTime", None):
                try:
                    if _to_secs(str(f.minTime)) > _to_secs(str(f.maxTime)):
                        raise HTTPException(status_code=400, detail=f"Field '{f.label}' has minTime greater than maxTime")
                except HTTPException:
                    raise
                except Exception:
                    raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid time range")
            if getattr(f, "timeStep", None) is not None:
                try:
                    step = int(f.timeStep)  # seconds
                    if step < 1:
                        raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid timeStep (must be >= 1)")
                except HTTPException:
                    raise
                except Exception:
                    raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid timeStep")

        # Count field validation
        if f.type == "count":
            try:
                minc = int(f.minCount) if getattr(f, "minCount", None) is not None else None
                maxc = int(f.maxCount) if getattr(f, "maxCount", None) is not None else None
                if minc is not None and minc < 0:
                    raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid minCount (must be >= 0)")
                if maxc is not None and maxc < 0:
                    raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid maxCount (must be >= 0)")
                if minc is not None and maxc is not None and minc > maxc:
                    raise HTTPException(status_code=400, detail=f"Field '{f.label}' has minCount greater than maxCount")
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Field '{f.label}' has non-integer minCount/maxCount")

        # Linear scale validation
        if f.type == "linear-scale":
            try:
                mins = int(f.minScale) if getattr(f, "minScale", None) is not None else 1
                maxs = int(f.maxScale) if getattr(f, "maxScale", None) is not None else 5
                if mins < 1 or maxs < 1:
                    raise HTTPException(status_code=400, detail=f"Field '{f.label}' has invalid scale (must be >= 1)")
                if mins > maxs:
                    raise HTTPException(status_code=400, detail=f"Field '{f.label}' has minScale greater than maxScale")
                # Clamp to a reasonable bound 1..10
                if maxs > 10:
                    raise HTTPException(status_code=400, detail=f"Field '{f.label}' has maxScale too large (<= 10)")
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Field '{f.label}' has non-integer minScale/maxScale")

    

def _create_id() -> str:
    return uuid.uuid4().hex


def _djb2_hash(s: str) -> str:
    try:
        h = 5381
        for ch in s:
            h = ((h << 5) + h) + ord(ch)
            h &= 0xFFFFFFFF
        return f"{h:08x}"
    except Exception:
        return uuid.uuid4().hex[:8]


def _stable_top_json(obj: Dict[str, Any] | None) -> str:
    try:
        if not obj:
            return "{}"
        keys = sorted(obj.keys())
        ordered = {k: obj.get(k) for k in keys}
        return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        try:
            return json.dumps(obj or {}, ensure_ascii=False)
        except Exception:
            return "{}"


def _deterministic_form_id(user_id: str | None, cfg: "FormConfig") -> str:
    """Build a deterministic ID from userId and a stable signature of key attributes.
    Falls back to random when userId is missing.
    """
    try:
        uid = (user_id or "").strip()
        basis = {
            "title": getattr(cfg, "title", "") or "",
            "formType": getattr(cfg, "formType", "simple") or "simple",
            # small signature from fields
            "fieldsSig": [
                {
                    "l": (getattr(f, "label", None) or ""),
                    "t": (getattr(f, "type", None) or ""),
                }
                for f in (getattr(cfg, "fields", []) or [])
            ],
        }
        sig = _djb2_hash(_stable_top_json(basis))
        if uid:
            return f"{uid}_{sig}"
        return f"form_{sig}"
    except Exception:
        return _create_id()

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
# Base directory where live certs are written
CERT_LIVE_BASE     = os.path.join(CERTBOT_CONFIG_DIR, "live")
# Ensure directories exist
os.makedirs(CERTBOT_CONFIG_DIR, exist_ok=True)
os.makedirs(CERTBOT_WORK_DIR, exist_ok=True)
os.makedirs(CERTBOT_LOGS_DIR, exist_ok=True)

# Renewal lock/state file
_RENEW_LOCK_FILE = os.path.join(os.getcwd(), "data", "letsencrypt", "renew.lock")
_RENEW_LAST_FILE = os.path.join(os.getcwd(), "data", "letsencrypt", "renew.last.json")

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


def _nginx_conf_http_multi(domains: List[str]) -> str:
    names = " ".join(domains)
    return f"""
server {{
    listen 80;
    server_name {names};

    location /.well-known/acme-challenge/ {{
        root {ACME_WEBROOT};
    }}

    return 301 https://$host$request_uri;
}}
""".strip()


def _nginx_conf_tls_multi(domains: List[str]) -> str:
    primary = domains[0]
    names = " ".join(domains)
    cert_base = os.path.join(CERT_LIVE_BASE, primary)
    form_redirect = ""
    if FRONTEND_URL:
        # Absolute redirect for SPA /form/* paths directly from Nginx to avoid proxy loops
        form_redirect = f"""
    location ^~ /form/ {{
        return 302 {FRONTEND_URL.rstrip('/')}$request_uri;
    }}
"""
    return f"""
server {{
    listen 80;
    server_name {names};

    location /.well-known/acme-challenge/ {{
        root {ACME_WEBROOT};
    }}

    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {names};

    ssl_certificate     {cert_base}/fullchain.pem;
    ssl_certificate_key {cert_base}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    location /.well-known/acme-challenge/ {{
        root {ACME_WEBROOT};
    }}

    {form_redirect}

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

def _nginx_conf_tls(domain: str) -> str:
    cert_base = os.path.join(CERT_LIVE_BASE, domain)
    form_redirect = ""
    if FRONTEND_URL:
        form_redirect = f"""
    location ^~ /form/ {{
        return 302 {FRONTEND_URL.rstrip('/')}$request_uri;
    }}
"""
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


 


def _shell(cmd) -> subprocess.CompletedProcess:
    """Run a command safely without invoking a shell.
    Accepts either a string (split via shlex) or a sequence of args.
    """
    try:
        if isinstance(cmd, str):
            args = shlex.split(cmd)
        else:
            args = list(cmd)
        return subprocess.run(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
    except Exception as e:
        # Return a CompletedProcess-like object on failure for callers expecting .stdout/.returncode
        try:
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=str(e))
        except Exception:
            # Fallback minimal object
            class _CP:
                def __init__(self, s):
                    self.args = cmd
                    self.returncode = 1
                    self.stdout = s
            return _CP(str(e))


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
FRONTEND_URL         = (os.getenv("FRONTEND_URL") or "").strip()
# Optional DNS-01 configuration for Certbot (provider plugin)
CERTBOT_DNS_PROVIDER      = os.getenv("CERTBOT_DNS_PROVIDER")  # e.g., 'cloudflare'
CERTBOT_DNS_CREDENTIALS   = os.getenv("CERTBOT_DNS_CREDENTIALS")  # path to credentials file


def _certbot_dir_flags() -> str:
    return (
        f" --config-dir {CERTBOT_CONFIG_DIR}"
        f" --work-dir {CERTBOT_WORK_DIR}"
        f" --logs-dir {CERTBOT_LOGS_DIR}"
    )


def _cert_status_for_domain(primary_domain: str) -> Dict[str, Any]:
    """Return certificate status for a domain from /etc/letsencrypt/live/<domain>/cert.pem.
    Uses openssl via _shell to extract subject, issuer, dates, and SANs.
    """
    live_dir = os.path.join(CERT_LIVE_BASE, primary_domain)
    cert_path = os.path.join(live_dir, "cert.pem")
    if not os.path.exists(cert_path):
        return {"exists": False, "domain": primary_domain}
    try:
        # Gather fields using safe subprocess (no shell)
        def _run_ssl(args):
            try:
                cp = subprocess.run(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
                return cp.stdout or ""
            except Exception:
                return ""
        out_subject = _run_ssl(["openssl", "x509", "-in", cert_path, "-noout", "-subject"])
        out_issuer  = _run_ssl(["openssl", "x509", "-in", cert_path, "-noout", "-issuer"])
        out_enddate = _run_ssl(["openssl", "x509", "-in", cert_path, "-noout", "-enddate"])
        out_start   = _run_ssl(["openssl", "x509", "-in", cert_path, "-noout", "-startdate"])
        out_san     = _run_ssl(["openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectAltName"])

        def _val(line: str) -> str:
            return (line.strip().split("=", 1)[-1] if "=" in line else line.strip())

        subject = _val(out_subject)
        issuer  = _val(out_issuer)
        not_after_raw = _val(out_enddate)
        not_before_raw = _val(out_start)
        # Extract SANs
        sans: List[str] = []
        try:
            # subjectAltName= DNS:example.com, DNS:www.example.com
            san_line = "".join(out_san.strip().splitlines())
            if "subjectAltName" in san_line and ":" in san_line:
                part = san_line.split(":", 1)[1]
                for tok in part.split(","):
                    tok = tok.strip()
                    if tok.startswith("DNS:"):
                        sans.append(tok[4:].strip())
        except Exception:
            pass

        # Compute days remaining
        def _parse_as_dt(s: str) -> Optional[datetime]:
            try:
                # Example: notAfter=Dec 27 20:13:11 2025 GMT
                v = s.strip()
                if v.lower().startswith("notafter="):
                    v = v.split("=", 1)[1].strip()
                if v.lower().startswith("notbefore="):
                    v = v.split("=", 1)[1].strip()
                # strptime format
                return datetime.strptime(v, "%b %d %H:%M:%S %Y %Z")
            except Exception:
                return None

        nb = _parse_as_dt(not_before_raw)
        na = _parse_as_dt(not_after_raw)
        days_remaining = None
        if na:
            try:
                days_remaining = max(0, (na - datetime.utcnow()).days)
            except Exception:
                days_remaining = None

        return {
            "exists": True,
            "domain": primary_domain,
            "subject": subject,
            "issuer": issuer,
            "notBefore": not_before_raw.strip(),
            "notAfter": not_after_raw.strip(),
            "daysRemaining": days_remaining,
            "sans": sans,
            "liveDir": live_dir,
        }
    except Exception as e:
        return {"exists": True, "domain": primary_domain, "error": str(e)}


def _certbot_renew_and_reload() -> Dict[str, Any]:
    """Run certbot renew and reload Nginx if changes applied."""
    if not (CERTBOT_BIN and shutil.which(CERTBOT_BIN)):
        return {"ok": False, "reason": "certbot not available"}
    dir_flags = _certbot_dir_flags()
    # Prefer relying on saved authenticators; include webroot for safety
    cmd = f"{CERTBOT_BIN} renew --agree-tos -n" + dir_flags + f" --webroot -w {ACME_WEBROOT}"
    res = _shell(cmd)
    changed = "No renewals were attempted" not in (res.stdout or "") and "No renewals were attempted" not in (res.stdout or "").lower()
    info: Dict[str, Any] = {"ok": res.returncode == 0, "changed": changed, "output": (res.stdout or "")[-8000:]}
    if res.returncode != 0:
        return info
    try:
        reload_out = _nginx_test_and_reload()
        info["nginx"] = reload_out
    except Exception as e:
        info["nginx_error"] = str(e)
    # write last run
    try:
        os.makedirs(os.path.dirname(_RENEW_LAST_FILE), exist_ok=True)
        with open(_RENEW_LAST_FILE, "w", encoding="utf-8") as f:
            json.dump({"ranAt": datetime.utcnow().isoformat(), "changed": bool(changed)}, f)
    except Exception:
        pass
    return info


def _start_cert_renew_daemon():
    """Start a single background thread (per host) to renew certs periodically.
    Uses a lock file to avoid multiple workers scheduling the same job.
    """
    try:
        # Try to acquire lock file exclusively
        if os.path.exists(_RENEW_LOCK_FILE):
            return
        os.makedirs(os.path.dirname(_RENEW_LOCK_FILE), exist_ok=True)
        with open(_RENEW_LOCK_FILE, "x", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except Exception:
        # Another process has the lock
        return

    def _loop():
        # Initial delay to allow app startup
        time.sleep(30)
        while True:
            try:
                _certbot_renew_and_reload()
            except Exception:
                pass
            # Sleep 12 hours between checks
            time.sleep(12 * 3600)

    try:
        t = threading.Thread(target=_loop, name="certbot-renew", daemon=True)
        t.start()
    except Exception:
        pass


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
# Geo helpers (country normalization imported from geo_restrictions)
# -----------------------------

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
    'admin','administrator','hostmaster','webmaster','postmaster','root','support','info','sales','contact','help','noreply','no-reply','abuse','billing','security','office','hr','hello','hi'
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

# Routes start here

# Public endpoint to fetch Geoapify API key from server env for the frontend
@router.get("/geoapify/key")
@limiter.limit("120/minute")
async def get_geoapify_key(request: Request):
    """Return the Geoapify API key from backend environment.
    The frontend uses this to call Geoapify directly from the client.
    """
    try:
        key = GEOAPIFY_API_KEY or ""
    except Exception:
        key = ""
    return {"key": key}

async def _ensure_form_abandons_table(session):
    try:
        await session.execute(text(
            """
            CREATE TABLE IF NOT EXISTS form_abandons (
                id TEXT PRIMARY KEY,
                form_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                user_id TEXT,
                values JSONB,
                filled_count INTEGER,
                total_fields INTEGER,
                progress TEXT,
                step INTEGER,
                total_steps INTEGER,
                submitted BOOLEAN DEFAULT FALSE,
                abandoned BOOLEAN DEFAULT FALSE,
                abandoned_at TIMESTAMPTZ,
                last_activity_at TIMESTAMPTZ,
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """
        ))
        # Helpful index for lookups
        await session.execute(text(
            """
            CREATE INDEX IF NOT EXISTS idx_form_abandons_form_session ON form_abandons(form_id, session_id);
            """
        ))
    except Exception:
        # Best effort; subsequent upserts may fail if DDL is not permitted
        pass

@router.post("/abandons/upsert")
@limiter.limit("240/minute")
async def upsert_abandon(request: Request, payload: Dict[str, Any] | None = None):
    """Upsert partial progress/abandonment state for a form session.
    Expects JSON body with at least: { formId, sessionId }.
    Other optional fields are persisted when provided by the frontend.
    Public endpoint (no auth) to avoid blocking anonymous submitters.
    """
    try:
        body = payload or {}
    except Exception:
        body = {}

    form_id = str((body.get("formId") or "").strip())
    session_id = str((body.get("sessionId") or "").strip())
    if not form_id or not session_id:
        raise HTTPException(status_code=400, detail="Missing formId or sessionId")

    # Prepare fields
    rec = {
        "id": f"{form_id}:{session_id}",
        "form_id": form_id,
        "session_id": session_id,
        "user_id": (body.get("userId") or None),
        "values": body.get("values") if isinstance(body.get("values"), (dict, list)) else None,
        "filled_count": _safe_int(body.get("filledCount")),
        "total_fields": _safe_int(body.get("totalFields")),
        "progress": (body.get("progress") or None),
        "step": _safe_int(body.get("step")),
        "total_steps": _safe_int(body.get("totalSteps")),
        "submitted": bool(body.get("submitted")) if body.get("submitted") is not None else False,
        "abandoned": bool(body.get("abandoned")) if body.get("abandoned") is not None else False,
        "abandoned_at": _safe_iso_dt(body.get("abandonedAt")),
        "last_activity_at": _safe_iso_dt(body.get("lastActivityAt")),
        "updated_at": _safe_iso_dt(body.get("updatedAt")) or datetime.utcnow(),
    }

    # Upsert
    try:
        # First ensure table exists and commit DDL operations separately
        async with async_session_maker() as ddl_session:
            try:
                await _ensure_form_abandons_table(ddl_session)
                await ddl_session.commit()
            except Exception:
                await ddl_session.rollback()
                pass  # Best effort; subsequent operations may fail if DDL is not permitted
        
        # Now use a fresh transaction for data operations
        async with async_session_maker() as session:
            try:
                # Detect available columns for form_abandons to handle environments with older schema
                try:
                    cols_res = await session.execute(
                        text(
                            """
                            SELECT column_name FROM information_schema.columns
                            WHERE table_name = 'form_abandons'
                            """
                        )
                    )
                    fa_cols = {str(r[0]) for r in cols_res}
                except Exception:
                    await session.rollback()
                    fa_cols = set()

                extended_cols = {
                    "id","form_id","session_id","user_id","values","filled_count","total_fields",
                    "progress","step","total_steps","submitted","abandoned","abandoned_at",
                    "last_activity_at","updated_at","created_at"
                }

                if extended_cols.issubset(fa_cols):
                    # Use extended schema upsert
                    await session.execute(
                        text(
                            """
                            INSERT INTO form_abandons (
                                id, form_id, session_id, user_id, values, filled_count, total_fields, progress,
                                step, total_steps, submitted, abandoned, abandoned_at, last_activity_at, updated_at
                            ) VALUES (
                                :id, :form_id, :session_id, :user_id, CAST(:values AS JSONB), :filled_count, :total_fields, :progress,
                                :step, :total_steps, :submitted, :abandoned, :abandoned_at, :last_activity_at, :updated_at
                            )
                            ON CONFLICT (id) DO UPDATE SET
                                user_id = EXCLUDED.user_id,
                                values = EXCLUDED.values,
                                filled_count = EXCLUDED.filled_count,
                                total_fields = EXCLUDED.total_fields,
                                progress = EXCLUDED.progress,
                                step = EXCLUDED.step,
                                total_steps = EXCLUDED.total_steps,
                                submitted = EXCLUDED.submitted,
                                abandoned = EXCLUDED.abandoned,
                                abandoned_at = COALESCE(EXCLUDED.abandoned_at, form_abandons.abandoned_at),
                                last_activity_at = COALESCE(EXCLUDED.last_activity_at, form_abandons.last_activity_at),
                                updated_at = EXCLUDED.updated_at
                            """
                        ),
                        {
                            **rec,
                            # Ensure JSONB binding works across drivers by serializing dict/list to text
                            "values": json.dumps(rec["values"]) if isinstance(rec["values"], (dict, list)) else None,
                        },
                    )
                else:
                    # Fallback to compact schema: id, form_id, data, created_at
                    payload = {
                        "sessionId": session_id,
                        "userId": rec["user_id"],
                        "values": rec["values"],
                        "filledCount": rec["filled_count"],
                        "totalFields": rec["total_fields"],
                        "progress": rec["progress"],
                        "step": rec["step"],
                        "totalSteps": rec["total_steps"],
                        "submitted": rec["submitted"],
                        "abandoned": rec["abandoned"],
                        "abandonedAt": body.get("abandonedAt"),
                        "lastActivityAt": body.get("lastActivityAt"),
                        "updatedAt": rec["updated_at"].isoformat() if hasattr(rec["updated_at"], "isoformat") else str(rec["updated_at"]),
                    }
                    await session.execute(
                        text(
                            """
                            INSERT INTO form_abandons (id, form_id, data, created_at)
                            VALUES (:id, :form_id, CAST(:data AS JSONB), NOW())
                            ON CONFLICT (id) DO UPDATE SET
                                data = EXCLUDED.data,
                                created_at = form_abandons.created_at
                            """
                        ),
                        {
                            "id": rec["id"],
                            "form_id": rec["form_id"],
                            "data": json.dumps(payload),
                        },
                    )
                await session.commit()
            except Exception as e:
                await session.rollback()
                raise
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("upsert_abandon failed form_id=%s session_id=%s error=%s", form_id, session_id, str(e))
        raise HTTPException(status_code=500, detail="Failed to save progress")

@router.get("/forms/{form_id}/abandons")
async def list_form_abandons(form_id: str, limit: int = 100):
    """List abandoned sessions for a form.
    Returns: { abandons: [{ id, sessionId, values, filledCount, totalFields, progress, abandonedAt, ... }] }
    """
    try:
        async with async_session_maker() as session:
            # Check if extended schema exists
            try:
                cols_res = await session.execute(
                    text(
                        """
                        SELECT column_name FROM information_schema.columns
                        WHERE table_name = 'form_abandons'
                        """
                    )
                )
                fa_cols = {str(r[0]) for r in cols_res}
            except Exception:
                fa_cols = set()

            extended_cols = {
                "id","form_id","session_id","user_id","values","filled_count","total_fields",
                "progress","step","total_steps","submitted","abandoned","abandoned_at",
                "last_activity_at","updated_at","created_at"
            }

            abandons = []
            if extended_cols.issubset(fa_cols):
                # Use extended schema
                result = await session.execute(
                    text(
                        """
                        SELECT 
                            id, session_id, user_id, values, filled_count, total_fields,
                            progress, step, total_steps, submitted, abandoned,
                            abandoned_at, last_activity_at, updated_at, created_at
                        FROM form_abandons
                        WHERE form_id = :fid AND abandoned = TRUE
                        ORDER BY abandoned_at DESC NULLS LAST
                        LIMIT :lim
                        """
                    ),
                    {"fid": form_id, "lim": limit}
                )
                rows = result.mappings().all()
                abandons = [
                    {
                        "id": row["id"],
                        "sessionId": row["session_id"],
                        "userId": row["user_id"],
                        "values": row["values"],
                        "filledCount": row["filled_count"],
                        "totalFields": row["total_fields"],
                        "progress": row["progress"],
                        "step": row["step"],
                        "totalSteps": row["total_steps"],
                        "submitted": row["submitted"],
                        "abandoned": row["abandoned"],
                        "abandonedAt": row["abandoned_at"].isoformat() if row["abandoned_at"] else None,
                        "lastActivityAt": row["last_activity_at"].isoformat() if row["last_activity_at"] else None,
                        "updatedAt": row["updated_at"].isoformat() if row["updated_at"] else None,
                        "createdAt": row["created_at"].isoformat() if row["created_at"] else None,
                    }
                    for row in rows
                ]
            else:
                # Fallback to compact schema
                result = await session.execute(
                    text(
                        """
                        SELECT id, form_id, data, created_at
                        FROM form_abandons
                        WHERE form_id = :fid
                        ORDER BY created_at DESC
                        LIMIT :lim
                        """
                    ),
                    {"fid": form_id, "lim": limit}
                )
                rows = result.mappings().all()
                for row in rows:
                    try:
                        data = row["data"] if isinstance(row["data"], dict) else {}
                        if data.get("abandoned"):
                            abandons.append({
                                "id": row["id"],
                                "sessionId": data.get("sessionId"),
                                "createdAt": row["created_at"].isoformat() if row["created_at"] else None,
                                **data
                            })
                    except Exception:
                        continue

        return {"abandons": abandons}
    except Exception as e:
        logger.exception("list abandons failed form_id=%s", form_id)
        raise HTTPException(status_code=500, detail=f"Failed to list abandoned sessions: {e}")

def _safe_int(v):
    try:
        if v is None:
            return None
        return int(v)
    except Exception:
        return None

def _safe_iso_dt(v):
    try:
        s = (v or "").strip()
        if not s:
            return None
        # Accept ISO strings, allow trailing Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None

@router.get("/forms/{form_id}")
async def public_get_form(form_id: str):
    """
    Public endpoint to get a published form by ID from Neon (PostgreSQL).
    Returns 404 only when the form does not exist or is not published.
    """
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                text("""
                    SELECT * FROM forms
                    WHERE id = :fid
                    LIMIT 1
                """),
                {"fid": form_id}
            )
            row = res.mappings().first()
            if not row or not bool(row.get("is_published")):
                raise HTTPException(status_code=404, detail="Form not found")
            # Enrich response with subtitle alias and submitButton defaults
            data = dict(row)
            try:
                if not data.get("subtitle") and data.get("description"):
                    data["subtitle"] = data.get("description")
            except Exception:
                pass
            try:
                theme = data.get("theme") or {}
                btn = (data.get("submitButton") or theme.get("submitButton") or {})
                primary = (theme.get("primaryColor") if isinstance(theme, dict) else None) or "#4f46e5"
                computed_btn = {
                    "label": (btn.get("label") if isinstance(btn, dict) else None) or "Submit",
                    "color": (btn.get("color") if isinstance(btn, dict) else None) or primary,
                    "textColor": (btn.get("textColor") if isinstance(btn, dict) else None) or "#ffffff",
                }
                # Ensure theme.submitButton exists for clients that read theme
                try:
                    if not isinstance(theme, dict):
                        theme = {}
                    theme = dict(theme)
                    theme["submitButton"] = computed_btn
                    data["theme"] = theme
                except Exception:
                    pass
            except Exception:
                # Best-effort; leave as-is on error
                pass
            # Map DB snake_case fields to frontend camelCase expected by SPA
            try:
                # Normalize JSON/text fields first
                def _json_or(val, default):
                    try:
                        if isinstance(val, str):
                            return json.loads(val)
                        return val if isinstance(val, (dict, list)) else default
                    except Exception:
                        return default

                # Best-effort: increment views in Neon and log to analytics table BEFORE returning
                try:
                    # Increment cached counter in forms table
                    await session.execute(
                        text("UPDATE forms SET views = COALESCE(views,0) + 1, updated_at = NOW() WHERE id = :fid"),
                        {"fid": form_id},
                    )
                    # Log view event to analytics table for accurate tracking
                    await session.execute(
                        text("""
                            INSERT INTO analytics (id, form_id, type, data, created_at)
                            VALUES (:id, :form_id, :type, :data, NOW())
                        """),
                        {
                            "id": _create_id(),
                            "form_id": form_id,
                            "type": "view",
                            "data": json.dumps({"source": "form_load"})
                        }
                    )
                    await session.commit()
                except Exception:
                    pass

                # Fetch owner's plan for upload limits
                owner_plan = "free"
                user_id = data.get("user_id") or data.get("userId")
                if user_id:
                    try:
                        plan_res = await session.execute(
                            text("SELECT plan FROM users WHERE uid = :uid LIMIT 1"),
                            {"uid": user_id}
                        )
                        plan_row = plan_res.mappings().first()
                        if plan_row and plan_row.get("plan"):
                            owner_plan = str(plan_row.get("plan")).strip().lower()
                    except Exception:
                        pass

                # Build camelCase payload
                out = {
                    "id": data.get("id"),
                    "userId": data.get("user_id") or data.get("userId"),
                    "ownerPlan": owner_plan,  # Include owner's plan for upload size limits
                    "title": data.get("title"),
                    "subtitle": data.get("subtitle"),
                    "description": data.get("description"),
                    "language": data.get("language") or "en",
                    "thankYouMessage": data.get("thankYouMessage") or data.get("thank_you_message") or "Thank you for your submission! We'll get back to you soon.",
                    "redirect": _json_or(data.get("redirect"), {}) or {},
                    "emailValidationEnabled": bool(data.get("email_validation_enabled") if data.get("email_validation_enabled") is not None else data.get("emailValidationEnabled")),
                    "professionalEmailsOnly": bool(data.get("professional_emails_only") if data.get("professional_emails_only") is not None else data.get("professionalEmailsOnly")),
                    "blockRoleEmails": bool(data.get("block_role_emails") if data.get("block_role_emails") is not None else data.get("blockRoleEmails")),
                    "emailRejectBadReputation": bool(data.get("email_reject_bad_reputation") if data.get("email_reject_bad_reputation") is not None else data.get("emailRejectBadReputation")),
                    "minDomainAgeDays": int(data.get("min_domain_age_days") or data.get("minDomainAgeDays") or 30),
                    "recaptchaEnabled": bool(data.get("recaptcha_enabled") if data.get("recaptcha_enabled") is not None else data.get("recaptchaEnabled")),
                    "urlScanEnabled": bool(data.get("url_scan_enabled") if data.get("url_scan_enabled") is not None else data.get("urlScanEnabled")),
                    "fileSafetyCheckEnabled": bool(data.get("file_safety_check_enabled") if data.get("file_safety_check_enabled") is not None else data.get("fileSafetyCheckEnabled")),
                    "gdprComplianceEnabled": bool(data.get("gdpr_compliance_enabled") if data.get("gdpr_compliance_enabled") is not None else data.get("gdprComplianceEnabled")),
                    "showPoweredBy": True if data.get("show_powered_by") is None and data.get("showPoweredBy") is None else bool(data.get("show_powered_by") if data.get("show_powered_by") is not None else data.get("showPoweredBy")),
                    "privacyPolicyUrl": data.get("privacyPolicyUrl") or data.get("privacy_policy_url") or "",
                    "passwordProtectionEnabled": bool(data.get("password_protection_enabled") if data.get("password_protection_enabled") is not None else data.get("passwordProtectionEnabled")),
                    "passwordHash": data.get("password_hash") or data.get("passwordHash"),
                    "preventDuplicateByIP": bool(data.get("prevent_duplicate_by_ip") if data.get("prevent_duplicate_by_ip") is not None else data.get("preventDuplicateByIP")),
                    "duplicateWindowHours": int(data.get("duplicate_window_hours") or data.get("duplicateWindowHours") or 24),
                    "restrictedCountries": _json_or(data.get("restricted_countries"), data.get("restrictedCountries") or []) or [],
                    "allowedCountries": _json_or(data.get("allowed_countries"), data.get("allowedCountries") or []) or [],
                    "isPublished": bool(data.get("is_published") if data.get("is_published") is not None else data.get("isPublished")),
                    "formType": data.get("formType") or data.get("form_type") or "simple",
                    # Large JSON blobs already normalized above
                    "theme": data.get("theme") or {},
                    "branding": _json_or(data.get("branding"), data.get("branding") or {}) or {},
                    "fields": _json_or(data.get("fields"), data.get("fields") or []) or [],
                }
                return out
            except Exception:
                # Fallback to original data shape
                return data
    except HTTPException:
        raise
    except Exception:
        # Avoid leaking internals; treat as not found for public endpoint
        raise HTTPException(status_code=404, detail="Form not found")

@router.put("/forms/{form_id}")
@limiter.limit("60/minute")
async def update_form(form_id: str, request: Request, payload: Dict[str, Any] | None = None):
    """Update core form properties in Neon.
    Allowed fields: name, title, subtitle, description, theme (JSON).
    Requires Firebase ID token and ownership of the form.
    """
    # Auth
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")

    payload = payload or {}
    name = payload.get("name")
    title = payload.get("title")
    subtitle = payload.get("subtitle")
    description = payload.get("description")
    theme = payload.get("theme")
    branding = payload.get("branding")
    redirect_cfg = payload.get("redirect")
    # Spam/GDPR flags and geo restrictions
    recaptcha_enabled = payload.get("recaptchaEnabled")
    gdpr_compliance_enabled = payload.get("gdprComplianceEnabled")
    privacy_policy_url = payload.get("privacyPolicyUrl") or payload.get("privacy_policy_url")
    restricted_countries = payload.get("restrictedCountries")
    # Link safety check (URL scanner)
    url_scan_enabled = payload.get("urlScanEnabled")
    # File safety check
    file_safety_check_enabled = payload.get("fileSafetyCheckEnabled")
    # Email validation flags/settings
    email_validation_enabled = payload.get("emailValidationEnabled")
    professional_emails_only = payload.get("professionalEmailsOnly")
    block_role_emails = payload.get("blockRoleEmails")
    email_reject_bad_rep = payload.get("emailRejectBadReputation")
    min_domain_age_days = payload.get("minDomainAgeDays")
    # Typography styles for title/subtitle (persist under theme JSON)
    title_style = payload.get("titleStyle")
    subtitle_style = payload.get("subtitleStyle")

    # Build dynamic SET clause
    sets = []
    params: Dict[str, Any] = {"fid": form_id}
    if isinstance(name, str):
        sets.append("name = :name")
        params["name"] = name.strip()
    if isinstance(title, str):
        sets.append("title = :title")
        params["title"] = title.strip()
    if isinstance(subtitle, str):
        sets.append("subtitle = :subtitle")
        params["subtitle"] = subtitle.strip()
    if isinstance(description, str):
        sets.append("description = :description")
        params["description"] = description.strip()
    if isinstance(redirect_cfg, dict):
        # Expect shape { enabled: bool, url: str }
        try:
            sets.append("redirect = CAST(:redirect AS JSONB)")
            params["redirect"] = json.dumps(redirect_cfg)
        except Exception:
            pass
    # Spam/GDPR flags and geo restrictions
    if isinstance(recaptcha_enabled, bool):
        sets.append("recaptcha_enabled = :recaptcha_enabled")
        params["recaptcha_enabled"] = recaptcha_enabled
    if isinstance(gdpr_compliance_enabled, bool):
        sets.append("gdpr_compliance_enabled = :gdpr_compliance_enabled")
        params["gdpr_compliance_enabled"] = gdpr_compliance_enabled
    if isinstance(privacy_policy_url, str):
        sets.append("privacy_policy_url = :privacy_policy_url")
        params["privacy_policy_url"] = privacy_policy_url.strip() if privacy_policy_url.strip() else None
    if isinstance(restricted_countries, list):
        try:
            norm = [str(c).strip().upper() for c in restricted_countries if str(c).strip()]
            sets.append("restricted_countries = CAST(:restricted_countries AS JSONB)")
            params["restricted_countries"] = json.dumps(norm)
        except Exception:
            pass
    # Link safety check (URL scanner)
    if isinstance(url_scan_enabled, bool):
        sets.append("url_scan_enabled = :url_scan_enabled")
        params["url_scan_enabled"] = url_scan_enabled
    # File safety check
    if isinstance(file_safety_check_enabled, bool):
        sets.append("file_safety_check_enabled = :file_safety_check_enabled")
        params["file_safety_check_enabled"] = file_safety_check_enabled
    # Email validation flags/settings
    if isinstance(email_validation_enabled, bool):
        sets.append("email_validation_enabled = :email_validation_enabled")
        params["email_validation_enabled"] = email_validation_enabled
    if isinstance(professional_emails_only, bool):
        sets.append("professional_emails_only = :professional_emails_only")
        params["professional_emails_only"] = professional_emails_only
    if isinstance(block_role_emails, bool):
        sets.append("block_role_emails = :block_role_emails")
        params["block_role_emails"] = block_role_emails
    if isinstance(email_reject_bad_rep, bool):
        sets.append("email_reject_bad_reputation = :email_reject_bad_reputation")
        params["email_reject_bad_reputation"] = email_reject_bad_rep
    try:
        # Accept numeric string or number
        if min_domain_age_days is not None:
            mdd = int(min_domain_age_days)
            sets.append("min_domain_age_days = :min_domain_age_days")
            params["min_domain_age_days"] = mdd
    except Exception:
        pass
    # Password protection: persist to Neon (accept camelCase and snake_case)
    password_protection_enabled = payload.get("passwordProtectionEnabled")
    if not isinstance(password_protection_enabled, bool):
        password_protection_enabled = payload.get("password_protection_enabled")
    if isinstance(password_protection_enabled, bool):
        sets.append("password_protection_enabled = :password_protection_enabled")
        params["password_protection_enabled"] = bool(password_protection_enabled)
    # Accept either a precomputed hash or a plaintext password (builder may send either)
    password_hash = payload.get("passwordHash") or payload.get("password_hash")
    password_plain = payload.get("password") or payload.get("passwordPlain") or payload.get("password_plain")
    if isinstance(password_hash, str) and password_hash.strip() != "":
        # Store provided hash as-is
        sets.append("password_hash = :password_hash")
        params["password_hash"] = password_hash.strip()
    elif isinstance(password_plain, str):
        pw = password_plain.strip()
        # Best-effort hashing: prefer bcrypt if available; else store as-is (not ideal, but functional)
        try:
            import bcrypt  # type: ignore
            hashed = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
            sets.append("password_hash = :password_hash")
            params["password_hash"] = hashed
        except Exception:
            # Fallback: store plaintext; consider securing later with a migration to hashed values
            sets.append("password_hash = :password_hash")
            params["password_hash"] = pw or None
    else:
        # If explicitly disabling protection and no password provided, clear hash to avoid stale secrets
        if password_protection_enabled is False:
            sets.append("password_hash = :password_hash")
            params["password_hash"] = None

    # Duplicate submissions by IP: persist flags (accept camelCase and snake_case)
    prevent_duplicate_by_ip = payload.get("preventDuplicateByIP")
    if not isinstance(prevent_duplicate_by_ip, bool):
        prevent_duplicate_by_ip = payload.get("prevent_duplicate_by_ip")
    if isinstance(prevent_duplicate_by_ip, bool):
        sets.append("prevent_duplicate_by_ip = :prevent_duplicate_by_ip")
        params["prevent_duplicate_by_ip"] = bool(prevent_duplicate_by_ip)

    duplicate_window_hours = payload.get("duplicateWindowHours")
    if duplicate_window_hours is None:
        duplicate_window_hours = payload.get("duplicate_window_hours")
    try:
        if duplicate_window_hours is not None:
            dwh = int(duplicate_window_hours)
            if dwh < 0:
                dwh = 0
            sets.append("duplicate_window_hours = :duplicate_window_hours")
            params["duplicate_window_hours"] = dwh
    except Exception:
        pass

    # Branding: persist JSON and translate removePoweredBy -> show_powered_by
    # Also accept explicit showPoweredBy/show_powered_by at top-level
    # Precompute potential show_powered_by value, but only set when provided
    _spb_provided = False
    _spb_value = None
    try:
        # From branding.removePoweredBy / branding.remove_powered_by
        if isinstance(branding, dict):
            # Persist branding JSON as-is
            try:
                sets.append("branding = CAST(:branding AS JSONB)")
                params["branding"] = json.dumps(branding)
            except Exception:
                pass
            if isinstance(branding.get("removePoweredBy"), bool):
                _spb_provided = True
                _spb_value = (not branding.get("removePoweredBy"))
            elif isinstance(branding.get("remove_powered_by"), bool):
                _spb_provided = True
                _spb_value = (not branding.get("remove_powered_by"))
        # Top-level explicit showPoweredBy/show_powered_by overrides branding mapping when present
        if isinstance(payload.get("showPoweredBy"), bool):
            _spb_provided = True
            _spb_value = bool(payload.get("showPoweredBy"))
        elif isinstance(payload.get("show_powered_by"), bool):
            _spb_provided = True
            _spb_value = bool(payload.get("show_powered_by"))
        if _spb_provided:
            sets.append("show_powered_by = :show_powered_by")
            params["show_powered_by"] = bool(_spb_value)
    except Exception:
        pass

    if isinstance(theme, dict):
        # Merge typography styles into theme if supplied
        try:
            if isinstance(title_style, dict):
                theme["titleStyle"] = title_style
            if isinstance(subtitle_style, dict):
                theme["subtitleStyle"] = subtitle_style
        except Exception:
            pass
        sets.append("theme = CAST(:theme AS JSONB)")
        params["theme"] = json.dumps(theme)
    if not sets:
        return {"success": True, "updated": 0}

    async with async_session_maker() as session:
        # Ownership check: prefer user_id
        res = await session.execute(
            text(
                """
                SELECT user_id FROM forms
                WHERE id = :fid
                LIMIT 1
                """
            ),
            {"fid": form_id},
        )
        owner_row = res.mappings().first()
        if not owner_row:
            raise HTTPException(status_code=404, detail="Form not found")
        form_user = (owner_row.get("user_id") or "").strip()
        if uid not in (form_user,):
            # If ownership columns are empty, allow update by any authenticated user who knows the ID (best-effort)
            if form_user:
                raise HTTPException(status_code=403, detail="Forbidden")
        # Filter SET clauses to existing columns to avoid ProgrammingError on missing columns
        try:
            cols_res = await session.execute(
                text(
                    """
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'forms'
                    """
                )
            )
            existing_cols = {r[0] for r in cols_res}
        except Exception:
            existing_cols = set(["id","user_id","title","name","description","form_type","is_published","views","submissions","submission_limit","fields","theme","branding","allowed_domains","idempotency_key","created_at","updated_at"])

        def _col_from_set(s: str) -> str:
            try:
                return s.split("=", 1)[0].strip().split()[0]
            except Exception:
                return ""

        filtered_sets = [s for s in sets if _col_from_set(s) in existing_cols]
        if filtered_sets:
            set_sql = ", ".join(filtered_sets) + ", updated_at = NOW()"
            sql = text(f"""
                UPDATE forms
                SET {set_sql}
                WHERE id = :fid
            """)
            # Keep only params referenced by the query
            import re as _re
            needed = set(_re.findall(r":([a-zA-Z_][a-zA-Z0-9_]*)", set_sql)) | {"fid"}
            exec_params = {k: v for k, v in params.items() if k in needed}
            exec_params["fid"] = form_id
            await session.execute(sql, exec_params)
        # If filtered out everything, skip base UPDATE; JSONB merges below may still run
        # If theme wasn't provided but individual styles were, upsert them into theme JSONB
        try:
            if not isinstance(theme, dict):
                if isinstance(title_style, dict):
                    await session.execute(
                        text(
                            """
                            UPDATE forms
                            SET theme = jsonb_set(COALESCE(theme, '{}'::jsonb), '{titleStyle}', CAST(:ts AS JSONB), true),
                                updated_at = NOW()
                            WHERE id = :fid
                            """
                        ),
                        {"fid": form_id, "ts": json.dumps(title_style)},
                    )
                if isinstance(subtitle_style, dict):
                    await session.execute(
                        text(
                            """
                            UPDATE forms
                            SET theme = jsonb_set(COALESCE(theme, '{}'::jsonb), '{subtitleStyle}', CAST(:ss AS JSONB), true),
                                updated_at = NOW()
                            WHERE id = :fid
                            """
                        ),
                        {"fid": form_id, "ss": json.dumps(subtitle_style)},
                    )
        except Exception:
            # Do not fail the entire request if style merge fails
            pass
        await session.commit()
        return {"success": True, "updated": 1}

@router.post("/forms/{form_id}/view")
@limiter.limit("600/minute")
async def increment_form_view(form_id: str, request: Request):
    """Increment a form's view count in Neon (PostgreSQL)."""
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                text("""
                    UPDATE forms
                    SET views = COALESCE(views, 0) + 1,
                        updated_at = NOW()
                    WHERE id = :fid
                """),
                {"fid": form_id}
            )
            await session.commit()
        # rowcount may be None on some drivers; treat as success when not zero-ish
        try:
            updated = int(res.rowcount or 0)
        except Exception:
            updated = 0
        if updated < 1:
            return {"ok": False, "reason": "not_found"}
        return {"ok": True, "updated": updated}
    except Exception:
        # Do not leak internals; return ok=false to avoid breaking the client
        return {"ok": False}

@router.get("/forms/{form_id}/views")
async def get_form_views(form_id: str):
    """Return current views counter for a form (debug-friendly, no auth)."""
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                text("SELECT views FROM forms WHERE id = :fid LIMIT 1"),
                {"fid": form_id},
            )
            row = res.mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="Form not found")
            return {"views": int(row.get("views") or 0)}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch views")

@router.get("/user/plan")
@limiter.limit("120/minute")
async def get_user_plan(request: Request, userId: str = Query(...)):
    """Return the plan for a given user from Neon (PostgreSQL).
    Response: { "plan": "free" | "pro" | "business" | "enterprise" }
    """
    try:
        uid = str(userId or "").strip()
        if not uid:
            raise HTTPException(status_code=400, detail="Missing userId")
        is_pro = await _is_pro_plan(uid)
        # We only know if the user is on a paid tier or not; return a simple mapping
        return {"plan": "pro" if is_pro else "free"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("get_user_plan failed userId=%s", userId)
        raise HTTPException(status_code=500, detail=str(e))

# -----------------------------
# Email integration status (Neon persistence)
# -----------------------------

async def _ensure_email_integrations_table(session):
    try:
        await session.execute(text(
            """
            CREATE TABLE IF NOT EXISTS email_integrations (
                uid TEXT PRIMARY KEY,
                google_connected BOOLEAN DEFAULT FALSE,
                microsoft_connected BOOLEAN DEFAULT FALSE,
                smtp_enabled BOOLEAN DEFAULT FALSE,
                smtp_host TEXT,
                smtp_port INTEGER,
                smtp_username TEXT,
                smtp_password TEXT,
                smtp_from_email TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            """
        ))
        # Add smtp_password and smtp_from_email columns if they don't exist (for existing tables)
        try:
            await session.execute(text(
                "ALTER TABLE email_integrations ADD COLUMN IF NOT EXISTS smtp_password TEXT"
            ))
            await session.execute(text(
                "ALTER TABLE email_integrations ADD COLUMN IF NOT EXISTS smtp_from_email TEXT"
            ))
        except Exception:
            pass
    except Exception:
        # Best-effort; subsequent queries may fail if DDL is not permitted
        pass

@router.get("/email/integration/status")
@limiter.limit("120/minute")
async def get_email_integration_status(request: Request, userId: Optional[str] = Query(default=None)):
    """Return email integration status for a user from Neon.
    Response: { google: bool, microsoft: bool, smtp: bool }
    """
    try:
        if not userId:
            # No user provided; return safe defaults
            return {"google": False, "microsoft": False, "smtp": False}
        async with async_session_maker() as session:
            await _ensure_email_integrations_table(session)
            await session.commit()
            res = await session.execute(
                text("""
                    SELECT google_connected, microsoft_connected, smtp_enabled
                    FROM email_integrations
                    WHERE uid = :uid
                    LIMIT 1
                """),
                {"uid": userId}
            )
            row = res.mappings().first()
            if not row:
                return {"google": False, "microsoft": False, "smtp": False}
            return {
                "google": bool(row.get("google_connected")) if row.get("google_connected") is not None else False,
                "microsoft": bool(row.get("microsoft_connected")) if row.get("microsoft_connected") is not None else False,
                "smtp": bool(row.get("smtp_enabled")) if row.get("smtp_enabled") is not None else False,
            }
    except Exception:
        # Do not leak errors; default to all false
        return {"google": False, "microsoft": False, "smtp": False}

@router.post("/email/smtp/save")
@limiter.limit("30/minute")
async def save_smtp_settings(request: Request, payload: Dict[str, Any] | None = None, userId: Optional[str] = Query(default=None)):
    """Save SMTP settings for a user in Neon DB including encrypted password.
    Expects JSON body: { host, port, username, password, fromEmail }
    Returns: { success: true }
    """
    try:
        if not userId:
            raise HTTPException(status_code=400, detail="Missing userId")
        payload = payload or {}
        host = str(payload.get("host") or "").strip()
        try:
            port = int(payload.get("port")) if payload.get("port") is not None else 0
        except Exception:
            port = 0
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "").strip()
        from_email = str(payload.get("fromEmail") or "").strip() or username
        
        # Basic validation
        if not host or port not in (465, 587) or not username or not password:
            raise HTTPException(status_code=400, detail="Enter SMTP host, port (465/587), username and password")
        
        # Encrypt password using Fernet
        encryption_key = os.getenv("SMTP_ENCRYPTION_KEY") or Fernet.generate_key().decode()
        fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
        encrypted_password = fernet.encrypt(password.encode()).decode()
        
        async with async_session_maker() as session:
            await _ensure_email_integrations_table(session)
            # Upsert SMTP settings with encrypted password
            await session.execute(
                text(
                    """
                    INSERT INTO email_integrations (uid, smtp_enabled, smtp_host, smtp_port, smtp_username, smtp_password, smtp_from_email, updated_at)
                    VALUES (:uid, TRUE, :host, :port, :username, :password, :from_email, NOW())
                    ON CONFLICT (uid) DO UPDATE SET
                        smtp_enabled = EXCLUDED.smtp_enabled,
                        smtp_host = EXCLUDED.smtp_host,
                        smtp_port = EXCLUDED.smtp_port,
                        smtp_username = EXCLUDED.smtp_username,
                        smtp_password = EXCLUDED.smtp_password,
                        smtp_from_email = EXCLUDED.smtp_from_email,
                        updated_at = NOW()
                    """
                ),
                {"uid": userId, "host": host, "port": port, "username": username, "password": encrypted_password, "from_email": from_email}
            )
            await session.commit()
            return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("save_smtp_settings failed uid=%s", userId)
        raise HTTPException(status_code=500, detail="Failed to save SMTP settings")

async def _get_user_smtp_settings(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve user's SMTP settings from Neon DB and decrypt password."""
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                text(
                    """
                    SELECT smtp_host, smtp_port, smtp_username, smtp_password, smtp_from_email
                    FROM email_integrations
                    WHERE uid = :uid AND smtp_enabled = TRUE
                    LIMIT 1
                    """
                ),
                {"uid": user_id}
            )
            row = res.mappings().first()
            if not row or not row.get("smtp_password"):
                return None
            
            # Decrypt password
            encryption_key = os.getenv("SMTP_ENCRYPTION_KEY")
            if not encryption_key:
                logger.warning("SMTP_ENCRYPTION_KEY not set; cannot decrypt password")
                return None
            
            fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
            decrypted_password = fernet.decrypt(row["smtp_password"].encode()).decode()
            
            return {
                "host": row["smtp_host"],
                "port": row["smtp_port"],
                "username": row["smtp_username"],
                "password": decrypted_password,
                "from_email": row["smtp_from_email"] or row["smtp_username"]
            }
    except Exception as e:
        logger.exception("Failed to retrieve SMTP settings for user_id=%s", user_id)
        return None

def _send_email_via_user_smtp(smtp_config: Dict[str, Any], to_email: str, subject: str, html_body: str) -> bool:
    """Send email using user's custom SMTP settings.
    Returns True if sent successfully, False otherwise.
    """
    try:
        host = smtp_config["host"]
        port = smtp_config["port"]
        username = smtp_config["username"]
        password = smtp_config["password"]
        from_email = smtp_config["from_email"]
        
        # Build MIME email
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content("Please view this email in an HTML-compatible email client.")
        msg.add_alternative(html_body, subtype="html")
        
        # Send via SMTP
        import ssl
        if port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as server:
                server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.ehlo()
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.ehlo()
                server.login(username, password)
                server.send_message(msg)
        
        logger.info("Email sent via user SMTP host=%s port=%s from=%s to=%s", host, port, from_email, to_email)
        return True
    except Exception as e:
        logger.exception("Failed to send email via user SMTP: %s", e)
        return False

async def _send_email_via_integration(user_id: str, to_email: str, subject: str, html_body: str) -> bool:
    """Try to send email using user's configured SMTP integration.
    Returns True if sent successfully, False otherwise.
    """
    smtp_config = await _get_user_smtp_settings(user_id)
    if not smtp_config:
        return False
    return _send_email_via_user_smtp(smtp_config, to_email, subject, html_body)

# -----------------------------
# -----------------------------
# AI Copilot endpoint
# -----------------------------

@router.post("/ai/copilot")
@limiter.limit("30/minute")
async def ai_copilot(request: Request, payload: Dict[str, Any] | None = None):
    """AI copilot for generating form field suggestions.
    Body: { prompt: string, language?: string, title?: string, tone?: string, currentFields?: array }
    Returns: { suggestions: { fields: array } }
    """
    payload = payload or {}
    prompt = (payload.get("prompt") or "").strip()
    
    # For now, return a default/fallback response since AI integration is optional
    # This prevents 404 errors and allows the frontend to use default fields
    
    # In the future, this could integrate with OpenAI or other AI services
    # For example:
    # openai_key = os.getenv("OPENAI_API_KEY")
    # if openai_key and prompt:
    #     # Call OpenAI API to generate field suggestions
    #     pass
    
    # Return empty suggestions to let frontend use its default fields
    return {
        "suggestions": {
            "fields": []
        }
    }

# -----------------------------
# reCAPTCHA verification endpoint
# -----------------------------

@router.post("/recaptcha/verify")
@limiter.limit("60/minute")
async def verify_recaptcha_endpoint(request: Request, payload: Dict[str, Any] | None = None):
    """Verify a reCAPTCHA token from the frontend (used during signup).
    Body: { token: string }
    Returns: { success: true } or raises HTTPException
    """
    payload = payload or {}
    token = (payload.get("token") or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Missing reCAPTCHA token")
    
    # Get client IP for verification
    client_ip = _client_ip(request)
    
    # Verify the token
    is_valid = _verify_recaptcha(token, client_ip)
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="reCAPTCHA verification failed")
    
    return {"success": True}

# -----------------------------
# Upload presign endpoints for R2 + theme updates persisted to Neon
# -----------------------------


def _ext_from_name_and_type(filename: Optional[str], content_type: Optional[str]) -> str:
    try:
        name = str(filename or '').lower()
        if name.endswith('.png'): return '.png'
        if name.endswith('.jpg') or name.endswith('.jpeg'): return '.jpg'
        if name.endswith('.webp'): return '.webp'
        if name.endswith('.gif'): return '.gif'
        ct = str(content_type or '').lower()
        if 'png' in ct: return '.png'
        if 'jpeg' in ct or 'jpg' in ct: return '.jpg'
        if 'webp' in ct: return '.webp'
        if 'gif' in ct: return '.gif'
        return '.png'
    except Exception:
        return '.png'

@router.post("/uploads/form-bg/presign")
@limiter.limit("30/minute")
async def presign_form_bg(request: Request, payload: Dict[str, Any] | None = None):
    """Create a presigned URL to upload a page background image to R2 and return its public URL."""
    payload = payload or {}
    filename = str(payload.get('filename') or 'background.png')
    content_type = str(payload.get('contentType') or 'image/png')
    ext = _ext_from_name_and_type(filename, content_type)
    key = f"backgrounds/{uuid.uuid4().hex}{ext}"
    try:
        s3 = _r2_client()
        params = {"Bucket": R2_BUCKET, "Key": key, "ContentType": content_type}
        upload_url = s3.generate_presigned_url('put_object', Params=params, ExpiresIn=900)
        public_url = _public_url_for_key(key)
        return {"uploadUrl": upload_url, "publicUrl": public_url, "headers": {"Content-Type": content_type}}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("presign_form_bg failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create upload URL")

@router.post("/uploads/submissions/presign")
@limiter.limit("60/minute")
async def presign_submission_file(request: Request, payload: Dict[str, Any] | None = None):
    """Create a presigned URL to upload a submission attachment to R2.
    Returns direct R2 public URL.

    Body: { formId?: string, fieldId?: string, filename: string, contentType: string }
    """
    payload = payload or {}
    form_id = str(payload.get('formId') or '').strip()
    field_id = str(payload.get('fieldId') or '').strip()
    filename = str(payload.get('filename') or 'file.bin')
    content_type = str(payload.get('contentType') or 'application/octet-stream')
    ext = _ext_from_name_and_type(filename, content_type)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", os.path.splitext(filename)[0] or 'file')
    uid = _create_id()
    # Organize under submissions/{formId or unknown}/
    owner = form_id if form_id else 'unknown'
    # Include field id when available to help later auditing
    suffix = f"_{field_id}" if field_id else ""
    key = f"submissions/{owner}/{uid}{suffix}{ext}"
    
    # Generate file ID for tracking
    file_id = uuid.uuid4().hex[:12]
    
    try:
        # Create presigned upload URL
        s3 = _r2_client()
        params = {"Bucket": R2_BUCKET, "Key": key, "ContentType": content_type}
        upload_url = s3.generate_presigned_url('put_object', Params=params, ExpiresIn=900)
        
        # Generate R2 public URL (direct, no shortening)
        r2_public_url = _public_url_for_key(key)
        
        # Store file metadata in database
        async with async_session_maker() as session:
            await session.execute(
                text("""
                    INSERT INTO submission_files (id, form_id, response_id, r2_key, filename, content_type, size_bytes)
                    VALUES (:id, :form_id, :response_id, :r2_key, :filename, :content_type, 0)
                    ON CONFLICT (id) DO NOTHING
                """),
                {
                    "id": file_id,
                    "form_id": form_id or "unknown",
                    "response_id": "pending",  # Updated after submission
                    "r2_key": key,
                    "filename": filename,
                    "content_type": content_type,
                }
            )
            await session.commit()
        
        return {
            "uploadUrl": upload_url,
            "publicUrl": r2_public_url,  # Direct R2 public URL
            "key": file_id,  # File ID for tracking
            "headers": {"Content-Type": content_type}
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("presign_submission_file failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create upload URL")

@router.post("/uploads/media/presign")
@limiter.limit("30/minute")
async def presign_media(request: Request, payload: Dict[str, Any] | None = None):
    """Create a presigned URL to upload a media asset (image/video) and return its public URL."""
    payload = payload or {}
    filename = str(payload.get('filename') or 'media.bin')
    content_type = str(payload.get('contentType') or 'application/octet-stream')
    kind = (payload.get('kind') or '').strip().lower()
    folder = 'media/images' if kind == 'image' else ('media/videos' if kind == 'video' else 'media/files')
    ext = _ext_from_name_and_type(filename, content_type)
    key = f"{folder}/{uuid.uuid4().hex}{ext}"
    try:
        s3 = _r2_client()
        params = {"Bucket": R2_BUCKET, "Key": key, "ContentType": content_type}
        upload_url = s3.generate_presigned_url('put_object', Params=params, ExpiresIn=900)
        public_url = _public_url_for_key(key)
        return {"uploadUrl": upload_url, "publicUrl": public_url, "headers": {"Content-Type": content_type}}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("presign_media failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create upload URL")

@router.post("/uploads/profile-photo/presign")
@limiter.limit("30/minute")
async def presign_profile_photo(request: Request, payload: Dict[str, Any] | None = None):
    """Create a presigned URL to upload a profile photo to R2 and return its public URL."""
    payload = payload or {}
    filename = str(payload.get('filename') or 'profile.jpg')
    content_type = str(payload.get('contentType') or 'image/jpeg')
    ext = _ext_from_name_and_type(filename, content_type)
    key = f"profile-photos/{uuid.uuid4().hex}{ext}"
    try:
        s3 = _r2_client()
        params = {"Bucket": R2_BUCKET, "Key": key, "ContentType": content_type}
        upload_url = s3.generate_presigned_url('put_object', Params=params, ExpiresIn=900)
        public_url = _public_url_for_key(key)
        return {"uploadUrl": upload_url, "publicUrl": public_url, "headers": {"Content-Type": content_type}}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("presign_profile_photo failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create upload URL")

@router.post("/uploads/profile-photo/upload")
@limiter.limit("30/minute")
async def upload_profile_photo(request: Request):
    """Fallback server-side upload for profile photo when direct upload fails (CORS issues)."""
    try:
        # Parse multipart form data
        form = await request.form()
        file = form.get('file')
        if not file:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Read file content
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Empty file")
        
        # Determine content type and extension
        content_type = file.content_type or 'image/jpeg'
        filename = getattr(file, 'filename', 'profile.jpg')
        ext = _ext_from_name_and_type(filename, content_type)
        
        # Generate R2 key
        key = f"profile-photos/{uuid.uuid4().hex}{ext}"
        
        # Upload directly to R2
        s3 = _r2_client()
        s3.put_object(
            Bucket=R2_BUCKET,
            Key=key,
            Body=content,
            ContentType=content_type
        )
        
        # Return public URL
        public_url = _public_url_for_key(key)
        return {"publicUrl": public_url}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("upload_profile_photo failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to upload photo")

@router.post("/forms/{form_id}/theme/page-bg")
@limiter.limit("120/minute")
async def update_theme_page_bg(request: Request, form_id: str, payload: Dict[str, Any] | None = None):
    """Persist page background image URL to Neon forms.theme.pageBackgroundImage."""
    url = str((payload or {}).get('publicUrl') or (payload or {}).get('url') or '').strip()
    if not url:
        raise HTTPException(status_code=400, detail="Missing publicUrl")
    async with async_session_maker() as session:
        await session.execute(
            text(
                """
                UPDATE forms
                SET theme = jsonb_set(COALESCE(theme, '{}'::jsonb), '{pageBackgroundImage}', CAST(:url AS JSONB), true),
                    updated_at = NOW()
                WHERE id = :fid
                """
            ),
            {"fid": form_id, "url": json.dumps(url)}
        )
        await session.commit()
    return {"ok": True, "publicUrl": url}


@router.post("/forms/{form_id}/theme/submit-button-label")
@limiter.limit("120/minute")
async def update_theme_submit_button_label(request: Request, form_id: str, payload: Dict[str, Any] | None = None):
    """Persist submit button label to Neon forms.theme.submitButtonLabel."""
    label = str((payload or {}).get('label') or '').strip() or 'Submit'
    async with async_session_maker() as session:
        await session.execute(
            text(
                """
                UPDATE forms
                SET theme = jsonb_set(COALESCE(theme, '{}'::jsonb), '{submitButtonLabel}', CAST(:label AS JSONB), true),
                    updated_at = NOW()
                WHERE id = :fid
                """
            ),
            {"fid": form_id, "label": json.dumps(label)}
        )
        await session.commit()
    return {"ok": True, "label": label}


@router.post("/forms/{form_id}/theme/submit-button-color")
@limiter.limit("120/minute")
async def update_theme_submit_button_color(request: Request, form_id: str, payload: Dict[str, Any] | None = None):
    """Persist submit button background color to Neon forms.theme.submitButtonColor."""
    color = str((payload or {}).get('color') or '').strip()
    if not color or not color.startswith('#'):
        raise HTTPException(status_code=400, detail="Invalid color hex")
    async with async_session_maker() as session:
        await session.execute(
            text(
                """
                UPDATE forms
                SET theme = jsonb_set(COALESCE(theme, '{}'::jsonb), '{submitButtonColor}', CAST(:color AS JSONB), true),
                    updated_at = NOW()
                WHERE id = :fid
                """
            ),
            {"fid": form_id, "color": json.dumps(color)}
        )
        await session.commit()
    return {"ok": True, "color": color}


@router.post("/forms/{form_id}/theme/submit-button-text-color")
@limiter.limit("120/minute")
async def update_theme_submit_button_text_color(request: Request, form_id: str, payload: Dict[str, Any] | None = None):
    """Persist submit button text color to Neon forms.theme.submitButtonTextColor."""
    text_color = str((payload or {}).get('textColor') or '').strip()
    if not text_color or not text_color.startswith('#'):
        raise HTTPException(status_code=400, detail="Invalid textColor hex")
    async with async_session_maker() as session:
        await session.execute(
            text(
                """
                UPDATE forms
                SET theme = jsonb_set(COALESCE(theme, '{}'::jsonb), '{submitButtonTextColor}', CAST(:text_color AS JSONB), true),
                    updated_at = NOW()
                WHERE id = :fid
                """
            ),
            {"fid": form_id, "text_color": json.dumps(text_color)}
        )
        await session.commit()
    return {"ok": True, "textColor": text_color}


@router.post("/forms/{form_id}/theme/title-style")
@limiter.limit("120/minute")
async def update_theme_title_style(request: Request, form_id: str, payload: Dict[str, Any] | None = None):
    """Persist title style (bold, italic, level) to Neon forms.theme.titleStyle."""
    payload = payload or {}
    title_style = {
        "bold": bool(payload.get('bold', True)),
        "italic": bool(payload.get('italic', False)),
        "level": max(1, min(6, int(payload.get('level', 1))))
    }
    async with async_session_maker() as session:
        await session.execute(
            text(
                """
                UPDATE forms
                SET theme = jsonb_set(COALESCE(theme, '{}'::jsonb), '{titleStyle}', CAST(:style AS JSONB), true),
                    updated_at = NOW()
                WHERE id = :fid
                """
            ),
            {"fid": form_id, "style": json.dumps(title_style)}
        )
        await session.commit()
    return {"ok": True, "titleStyle": title_style}


@router.post("/forms/{form_id}/theme/subtitle-style")
@limiter.limit("120/minute")
async def update_theme_subtitle_style(request: Request, form_id: str, payload: Dict[str, Any] | None = None):
    """Persist subtitle style (bold, italic, level) to Neon forms.theme.subtitleStyle."""
    payload = payload or {}
    subtitle_style = {
        "bold": bool(payload.get('bold', False)),
        "italic": bool(payload.get('italic', False)),
        "level": max(1, min(6, int(payload.get('level', 3))))
    }
    async with async_session_maker() as session:
        await session.execute(
            text(
                """
                UPDATE forms
                SET theme = jsonb_set(COALESCE(theme, '{}'::jsonb), '{subtitleStyle}', CAST(:style AS JSONB), true),
                    updated_at = NOW()
                WHERE id = :fid
                """
            ),
            {"fid": form_id, "style": json.dumps(subtitle_style)}
        )
        await session.commit()
    return {"ok": True, "subtitleStyle": subtitle_style}


@router.post("/forms/{form_id}/auto-reply/config")
@limiter.limit("60/minute")
async def set_auto_reply_config(form_id: str, request: Request, payload: Dict[str, Any] | None = None):
    """Update auto-reply configuration on a form.
    Body: { enabled?: bool, emailFieldId?: string, subject?: string, messageHtml?: string }
    Requires Firebase auth and form ownership.
    """
    # Auth
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
    payload = payload or {}
    enabled = payload.get("enabled")
    email_field_id = payload.get("emailFieldId")
    subject = payload.get("subject")
    message_html = payload.get("messageHtml")

    # Persist into theme JSONB to avoid schema drift issues
    patch: Dict[str, Any] = {}
    if isinstance(enabled, bool):
        patch["autoReplyEnabled"] = enabled
    if isinstance(email_field_id, str):
        patch["autoReplyEmailFieldId"] = email_field_id.strip()
    if isinstance(subject, str):
        patch["autoReplySubject"] = subject.strip()
    if isinstance(message_html, str):
        patch["autoReplyMessageHtml"] = message_html
    if not patch:
        return {"success": True, "updated": 0}

    async with async_session_maker() as session:
        # Ownership check
        res = await session.execute(
            text("SELECT user_id FROM forms WHERE id = :fid LIMIT 1"),
            {"fid": form_id},
        )
        row = res.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Form not found")
        form_user = (row.get("user_id") or "").strip()
        if uid not in (form_user,):
            if form_user:
                raise HTTPException(status_code=403, detail="Forbidden")

        await session.execute(
            text(
                """
                UPDATE forms
                SET theme = COALESCE(theme, '{}'::jsonb) || CAST(:patch AS JSONB),
                    updated_at = NOW()
                WHERE id = :fid
                """
            ),
            {"fid": form_id, "patch": json.dumps(patch)},
        )
        await session.commit()
        return {"success": True, "updated": 1}

async def _ensure_submissions_indexes(session):
    """Create helpful indexes for submissions table if missing (best-effort)."""
    try:
        await session.execute(text(
            """
            CREATE INDEX IF NOT EXISTS idx_submissions_owner_month
            ON submissions (form_owner_id, submitted_at);
            """
        ))
    except Exception:
        pass
    try:
        await session.execute(text(
            """
            CREATE INDEX IF NOT EXISTS idx_submissions_form_date
            ON submissions (form_id, submitted_at);
            """
        ))
    except Exception:
        pass
    try:
        await session.execute(text(
            """
            CREATE INDEX IF NOT EXISTS idx_submissions_form_ip_date
            ON submissions (form_id, ip_address, submitted_at);
            """
        ))
    except Exception:
        pass


@router.post("/forms/{form_id}/theme/split-image")
@limiter.limit("120/minute")
async def update_theme_split_image(request: Request, form_id: str, payload: Dict[str, Any] | None = None):
    """Persist split view image URL to Neon forms.theme.splitImageUrl."""
    url = str((payload or {}).get('publicUrl') or (payload or {}).get('url') or '').strip()
    if not url:
        raise HTTPException(status_code=400, detail="Missing publicUrl")
    async with async_session_maker() as session:
        await session.execute(
            text(
                """
                UPDATE forms
                SET theme = jsonb_set(COALESCE(theme, '{}'::jsonb), '{splitImageUrl}', CAST(:url AS JSONB), true),
                    updated_at = NOW()
                WHERE id = :fid
                """
            ),
            {"fid": form_id, "url": json.dumps(url)}
        )
        await session.commit()
    return {"ok": True, "publicUrl": url}


@router.post("/forms/{form_id}/sessions/{session_id}/finalize")
@limiter.limit("60/minute")
async def finalize_session(form_id: str, session_id: str, request: Request, payload: Dict[str, Any] | None = None):
    """Finalize a session recording by storing R2 URL and metadata.
    Body: { r2Url?: string, recordingName?: string, duration?: number, country?: string }
    Returns: { ok: true }
    """
    payload = payload or {}
    r2_url = (payload.get("r2Url") or "").strip() or None
    recording_name = (payload.get("recordingName") or "").strip() or None
    duration = payload.get("duration")
    country = (payload.get("country") or "").strip().upper() or None
    
    # Convert duration to int if provided
    if duration is not None:
        try:
            duration = int(duration)
        except (ValueError, TypeError):
            duration = None
    
    try:
        async with async_session_maker() as session:
            # Upsert into sessions table
            await session.execute(
                text(
                    """
                    INSERT INTO sessions (id, form_id, r2_url, recording_name, duration, country_code, created_at)
                    VALUES (:sid, :fid, :r2_url, :rec_name, :dur, :country, NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        r2_url = COALESCE(EXCLUDED.r2_url, sessions.r2_url),
                        recording_name = COALESCE(EXCLUDED.recording_name, sessions.recording_name),
                        duration = COALESCE(EXCLUDED.duration, sessions.duration),
                        country_code = COALESCE(EXCLUDED.country_code, sessions.country_code)
                    """
                ),
                {
                    "sid": session_id,
                    "fid": form_id,
                    "r2_url": r2_url,
                    "rec_name": recording_name,
                    "dur": duration,
                    "country": country
                }
            )
            await session.commit()
        
        return {"ok": True}
    except Exception as e:
        logger.exception("finalize_session failed form_id=%s session_id=%s", form_id, session_id)
        raise HTTPException(status_code=500, detail="Failed to finalize session")


@router.post("/forms/{form_id}/submit")
@limiter.limit("5/minute")
async def submit_form(form_id: str, request: Request, payload: Dict = None):
    """Simple submission endpoint that enforces country restrictions.
    On success returns {success: True, message, redirectUrl?}.
    """
    # Load the form from Neon (PostgreSQL); require that it's published
    owner_email = None  # Will be fetched early to avoid transaction conflicts
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                text(
                    """
                    SELECT * FROM forms
                    WHERE id = :fid
                    LIMIT 1
                    """
                ),
                {"fid": form_id},
            )
            row = res.mappings().first()
        if not row or not bool(row.get("is_published")):
            raise HTTPException(status_code=404, detail="Form not found")
        form_data = dict(row)
        
        # Fetch owner email from Neon early (before transactions) to use for notifications later
        owner_id = str(form_data.get("user_id") or "").strip() or None
        if owner_id:
            owner_email = await get_owner_email(owner_id)
        # Normalize JSON fields that may be stored as text
        for k in ("theme", "branding"):
            v = form_data.get(k)
            if isinstance(v, str):
                try:
                    form_data[k] = json.loads(v)
                except Exception:
                    form_data[k] = {}
            elif not isinstance(v, dict):
                form_data[k] = {}
        
        # Fields is an array, handle separately
        v = form_data.get("fields")
        if isinstance(v, str):
            try:
                form_data["fields"] = json.loads(v)
            except Exception:
                form_data["fields"] = []
        elif not isinstance(v, list):
            form_data["fields"] = []
    except HTTPException:
        raise
    except Exception:
        # Avoid leaking internals; treat as not found for public submission
        raise HTTPException(status_code=404, detail="Form not found")

    # Submission limit enforcement (Neon-backed counts)
    try:
        limit_raw = form_data.get("submissionLimit")
        limit = int(limit_raw) if limit_raw is not None else 0

        # Monthly per-user submissions limit for Free plans
        try:
            owner_id = str(form_data.get("user_id") or "").strip() or None
            if owner_id and not (await _is_pro_plan(owner_id)):
                # Count current month's submissions for this owner in Neon
                async with async_session_maker() as session:
                    res = await session.execute(
                        text(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM submissions
                            WHERE form_owner_id = :uid
                              AND submitted_at >= date_trunc('month', NOW())
                            """
                        ),
                        {"uid": owner_id},
                    )
                    month_count = int((res.mappings().first() or {}).get("cnt") or 0)
                if month_count >= FREE_MONTHLY_SUBMISSION_LIMIT:
                    raise HTTPException(status_code=429, detail=f"Monthly submission limit reached ({FREE_MONTHLY_SUBMISSION_LIMIT}). Please try again next month or upgrade your plan.")
        except HTTPException:
            raise
        except Exception:
            # Do not fail submission on unexpected error here
            pass
        if limit and limit > 0:
            # Count total submissions for this form in Neon
            async with async_session_maker() as session:
                res = await session.execute(
                    text(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM submissions
                        WHERE form_id = :fid
                        """
                    ),
                    {"fid": form_id},
                )
                current = int((res.mappings().first() or {}).get("cnt") or 0)
            if current >= limit:
                raise HTTPException(status_code=429, detail="I'm sorry, we've reached the capacity limit, we cannot accept new submissions at this moment")
    except HTTPException:
        raise
    except Exception:
        # Fail open on unexpected errors
        pass

    # Determine if owner has Pro plan (fallback to Free if unknown)
    try:
        owner_id = str(form_data.get("user_id") or "").strip() or None
    except Exception:
        owner_id = None
    is_pro = await _is_pro_plan(owner_id)

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
    if allowed or restricted:
        detected, country = _country_from_ip(ip)
        
        # If country detection failed and restrictions are enabled, block (fail closed for security)
        if not detected or not country:
            logger.warning("geo: country detection failed for ip=%s, blocking due to active restrictions", ip)
            raise HTTPException(status_code=403, detail="We're sorry, but submissions from your country are currently restricted due to regional limitations.")
        
        # Check allowed countries (whitelist)
        if allowed and country not in allowed:
            logger.info("geo: blocked submission from %s (not in allowed list)", country)
            raise HTTPException(status_code=403, detail="We're sorry, but submissions from your country are currently restricted due to regional limitations.")
        
        # Check restricted countries (blacklist)
        if restricted and country in restricted:
            logger.info("geo: blocked submission from %s (in restricted list)", country)
            raise HTTPException(status_code=403, detail="We're sorry, but submissions from your country are currently restricted due to regional limitations.")

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
                    is_email_field = (ftype == "email") or (ftype in ("text", "textarea") and "email" in label.lower())
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

    # Duplicate submission check by IP within a time window (Neon-backed)
    if bool(form_data.get("preventDuplicateByIP")):
        try:
            window_hours = int(form_data.get("duplicateWindowHours") or 24)
        except Exception:
            window_hours = 24
        try:
            from datetime import timedelta
            threshold = datetime.utcnow() - timedelta(hours=max(1, window_hours))
            ip = ip or _client_ip(request)
            if ip:
                async with async_session_maker() as session:
                    res = await session.execute(
                        text(
                            """
                            SELECT 1
                            FROM submissions
                            WHERE form_id = :fid
                              AND ip_address = :ip
                              AND submitted_at >= :th
                            LIMIT 1
                            """
                        ),
                        {"fid": form_id, "ip": ip, "th": threshold},
                    )
                    if res.first() is not None:
                        raise HTTPException(status_code=429, detail="Duplicate submission detected from this IP. Please try again later.")
        except HTTPException:
            raise
        except Exception:
            # Fail open on dedupe errors
            pass

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
    resp: Dict[str, Optional[str] | bool | Dict] = {
        "success": True,
        "message": form_data.get("thankYouMessage"),
    }
    redir = form_data.get("redirect") or {}
    if redir.get("enabled") and redir.get("url"):
        resp["redirectUrl"] = redir.get("url")

    # Persist submission in Neon (store answers and metadata)
    # Use a real datetime object so Postgres stores TIMESTAMPTZ and comparisons work
    submitted_at = datetime.utcnow()
    response_id = uuid.uuid4().hex

    # Only persist answers for known fields, keyed by field LABEL for readability
    # Iterate through fields_def in the exact order they appear in forms.fields to preserve field order
    answers: Dict[str, object] = {}  # Python 3.7+ dicts maintain insertion order
    signatures: Dict[str, Dict[str, str]] = {}
    fields_def = form_data.get("fields") or []  # This is already ordered from DB
    payload = payload or {}
    
    logger.info("Processing submission form_id=%s fields_count=%d payload_keys=%s", form_id, len(fields_def), list(payload.keys()))
    
    try:
        for f in fields_def:
            try:
                fid = str(f.get("id"))
                label = str(f.get("label") or "Untitled")
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
                async def _file_to_url(v):
                    try:
                        if isinstance(v, dict):
                            u = v.get("url") or v.get("publicUrl") or v.get("downloadUrl")
                            k = str(v.get("key") or v.get("r2Key") or "").strip()
                            
                            # Always use direct R2 public URL
                            if u:
                                return _normalize_bg_public_url(str(u))
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
                    import asyncio
                    answers[label] = await asyncio.gather(*[_file_to_url(x) for x in val])
                else:
                    answers[label] = await _file_to_url(val)
            elif ftype == "signature" and val is not None:
                # Persist signature PNG to R2 when provided as a data URL and return status 'signed' with a PNG URL
                try:
                    # Accept either data URL string or object with dataUrl
                    data_url = None
                    if isinstance(val, str):
                        data_url = val.strip()
                    elif isinstance(val, dict):
                        data_url = str((val.get("dataUrl") or val.get("dataURL") or val.get("pngDataUrl") or "")).strip()
                    if data_url and data_url.startswith("data:image/") and ";base64," in data_url:
                        head, b64 = data_url.split(",", 1)
                        try:
                            raw = base64.b64decode(b64, validate=False)
                        except Exception:
                            raw = b""
                        if raw:
                            # Always store as PNG for consistency
                            key = f"submissions/{form_id}/{response_id}_{fid}.png"
                            sig_id = uuid.uuid4().hex[:12]  # Clean signature ID
                            
                            try:
                                # Upload signature to R2
                                s3 = _r2_client()
                                s3.put_object(Bucket=R2_BUCKET, Key=key, Body=raw, ContentType="image/png")
                                
                                # Store signature metadata in database
                                async with async_session_maker() as sig_session:
                                    await sig_session.execute(
                                        text("""
                                            INSERT INTO submission_signatures (id, form_id, response_id, field_id, r2_key, filename)
                                            VALUES (:id, :form_id, :response_id, :field_id, :r2_key, :filename)
                                            ON CONFLICT (id) DO NOTHING
                                        """),
                                        {
                                            "id": sig_id,
                                            "form_id": form_id,
                                            "response_id": response_id,
                                            "field_id": fid,
                                            "r2_key": key,
                                            "filename": f"signature_{fid}.png",
                                        }
                                    )
                                    await sig_session.commit()
                                
                                # Always use direct R2 public URL
                                r2_url = _public_url_for_key(key)
                                sig = {"status": "signed", "url": r2_url, "pngUrl": r2_url, "key": sig_id}
                                
                                signatures[label] = sig
                                answers[label] = sig
                                continue
                            except Exception:
                                # Fall through to store data URL if upload fails
                                pass
                    # Fallback: store minimal structure with status and a PNG data URL
                    meta = {"status": "signed", "dataUrl": data_url or str(val)}
                    # Alias as pngDataUrl for consumers expecting a PNG field
                    if data_url:
                        meta["pngDataUrl"] = data_url
                    signatures[label] = meta
                    answers[label] = meta
                except Exception:
                    # On unexpected error, still record that a signature was provided
                    try:
                        meta = {"status": "signed", "value": str(val)}
                        signatures[label] = meta
                    except Exception:
                        continue
            elif ftype == "zoom-meeting" and val is not None:
                # Create Zoom meeting automatically
                try:
                    meeting_data = val if isinstance(val, dict) else {}
                    topic = meeting_data.get("topic", "Meeting")
                    date = meeting_data.get("date", "")
                    time = meeting_data.get("time", "")
                    duration = int(meeting_data.get("duration", 30))
                    agenda = meeting_data.get("agenda", "")
                    
                    # Only create if we have date and time
                    if topic and date and time:
                        # Get user's Zoom token
                        async with async_session_maker() as zoom_session:
                            zoom_result = await zoom_session.execute(
                                text("""
                                    SELECT access_token FROM zoom_integrations
                                    WHERE uid = :uid
                                """),
                                {"uid": owner_id}
                            )
                            zoom_row = zoom_result.fetchone()
                            
                            if zoom_row and zoom_row[0]:
                                access_token = zoom_row[0]
                                
                                # Combine date and time into ISO 8601 format
                                start_time = f"{date}T{time}:00"
                                
                                # Create Zoom meeting via API
                                import requests
                                zoom_response = requests.post(
                                    "https://api.zoom.us/v2/users/me/meetings",
                                    headers={
                                        "Authorization": f"Bearer {access_token}",
                                        "Content-Type": "application/json"
                                    },
                                    json={
                                        "topic": topic,
                                        "type": 2,
                                        "start_time": start_time,
                                        "duration": duration,
                                        "timezone": "UTC",
                                        "agenda": agenda,
                                        "settings": {
                                            "host_video": True,
                                            "participant_video": True,
                                            "join_before_host": False,
                                            "mute_upon_entry": True,
                                            "waiting_room": True,
                                            "audio": "both"
                                        }
                                    },
                                    timeout=20
                                )
                                
                                if zoom_response.status_code == 201:
                                    meeting = zoom_response.json()
                                    # Store meeting details in answers
                                    answers[label] = {
                                        "topic": topic,
                                        "date": date,
                                        "time": time,
                                        "duration": duration,
                                        "agenda": agenda,
                                        "meeting_id": meeting.get("id"),
                                        "join_url": meeting.get("join_url"),
                                        "start_url": meeting.get("start_url"),
                                        "password": meeting.get("password"),
                                        "created": True
                                    }
                                    logger.info(f"Zoom meeting created: {meeting.get('id')} for form {form_id}")
                                else:
                                    # Failed to create meeting, store original data
                                    answers[label] = {**meeting_data, "created": False, "error": "Failed to create meeting"}
                                    logger.error(f"Zoom meeting creation failed: {zoom_response.status_code} - {zoom_response.text}")
                            else:
                                # Zoom not connected, store original data
                                answers[label] = {**meeting_data, "created": False, "error": "Zoom not connected"}
                    else:
                        # Missing required fields
                        answers[label] = {**meeting_data, "created": False}
                except Exception as e:
                    # Log error but don't fail submission
                    logger.exception(f"Zoom meeting creation error: {e}")
                    answers[label] = val
            else:
                # Store all other field types (text, email, number, etc.)
                if val is not None:
                    # Transform price fields from JSON to simple string format (e.g., USD2000.00)
                    if ftype == "price" and isinstance(val, dict):
                        amount = val.get("amount", "")
                        currency = val.get("currency", "USD")
                        # Format as CURRENCY + AMOUNT (e.g., USD2000.00 or USD2000)
                        try:
                            # Remove trailing .00 if amount is whole number
                            amt_float = float(str(amount))
                            if amt_float == int(amt_float):
                                answers[label] = f"{currency}{int(amt_float)}"
                            else:
                                answers[label] = f"{currency}{amount}"
                        except Exception:
                            # Fallback to direct concatenation
                            answers[label] = f"{currency}{amount}"
                    else:
                        answers[label] = val
        # Server-side price min/max validation using built answers
        try:
            for f in fields_def:
                try:
                    if str((f.get("type") or "")).strip().lower() != "price":
                        continue
                    label = str(f.get("label") or "Price")
                    if not label:
                        continue
                    amt_raw = None
                    v = answers.get(label)
                    if isinstance(v, dict):
                        amt_raw = v.get("amount")
                    elif isinstance(v, (str, int, float)):
                        amt_raw = v
                    if amt_raw in (None, ""):
                        # If required and empty, earlier required check should catch; skip here
                        continue
                    try:
                        amount = float(str(amt_raw))
                    except Exception:
                        continue
                    try:
                        min_p = f.get("minPrice")
                        max_p = f.get("maxPrice")
                        min_v = float(min_p) if min_p is not None else None
                        max_v = float(max_p) if max_p is not None else None
                    except Exception:
                        min_v = None
                        max_v = None
                    if (min_v is not None) and (amount < min_v):
                        raise HTTPException(status_code=400, detail=f"Minimum allowed is {min_v} for '{label}'.")
                    if (max_v is not None) and (amount > max_v):
                        raise HTTPException(status_code=400, detail=f"Maximum allowed is {max_v} for '{label}'.")
                except HTTPException:
                    raise
                except Exception:
                    continue
        except HTTPException:
            raise
        except Exception:
            # Fail closed on malformed validation config
            raise HTTPException(status_code=400, detail="Validation failed for one or more fields")
    except Exception as e:
        # Log but re-raise to prevent submission with empty answers
        logger.exception("submit_form answer processing error id=%s", form_id)
        raise HTTPException(status_code=500, detail=f"Failed to process form submission: {str(e)}")
    
    logger.info("Collected answers form_id=%s answer_count=%d answer_keys=%s", form_id, len(answers), list(answers.keys()))
    
    # Build a small ZIP manifest of file URLs (best-effort)
    files_zip_meta = None
    try:
        from io import BytesIO
        import zipfile as _zip
        buf = BytesIO()
        added = 0
        with _zip.ZipFile(buf, mode="w", compression=_zip.ZIP_DEFLATED) as zf:
            for f in fields_def:
                try:
                    if str((f.get("type") or "")).strip().lower() != "file":
                        continue
                    label = str(f.get("label") or "Untitled")
                    av2 = answers.get(label)
                    srcs = av2 if isinstance(av2, list) else ([av2] if av2 is not None else [])
                    for idx, v2 in enumerate(srcs):
                        url2 = None
                        if isinstance(v2, str):
                            url2 = v2
                        elif isinstance(v2, dict) and v2.get("url"):
                            url2 = str(v2.get("url"))
                        if not url2:
                            continue
                        # Use label-based filename for better readability
                        safe_label = label.replace(" ", "_").replace("/", "_")
                        zf.writestr(f"{safe_label}_{idx+1}.txt", url2)
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
        files_zip_meta = None

    # Geo enrich and insert into Neon in one transaction
    country_code, lat, lon = _geo_from_ip(ip)
    owner_id = form_data.get("user_id")
    # Build metadata payload
    meta_payload: Dict[str, Any] = {
        "clientIp": ip,
        "userAgent": str(request.headers.get("user-agent") or ""),
        "lat": lat,
        "lon": lon,
        "country": country_code,
    }
    if isinstance(signatures, dict) and signatures:
        meta_payload["signatures"] = signatures
    if files_zip_meta:
        meta_payload["filesZip"] = files_zip_meta

    async with async_session_maker() as session:
        await _ensure_submissions_indexes(session)
        # Insert submission row
        await session.execute(
            text(
                """
                INSERT INTO submissions (
                    id, form_id, form_owner_id, data, metadata,
                    ip_address, country_code, user_agent, submitted_at
                ) VALUES (
                :id, :form_id, :owner_id, CAST(:data AS JSONB), CAST(:metadata AS JSONB),
                :ip, :country, :ua, :submitted_at
            )
            """
            ),
            {
                "id": response_id,
                "form_id": form_id,
                "owner_id": owner_id,
                # Preserve field order: sort_keys=False maintains insertion order from fields_def iteration
                "data": json.dumps(answers or {}, ensure_ascii=False, sort_keys=False),
                "metadata": json.dumps(meta_payload, ensure_ascii=False, sort_keys=False),
                "ip": ip,
                "country": (country_code or "").upper() or None,
                "ua": str(request.headers.get("user-agent") or ""),
                "submitted_at": submitted_at,
            },
        )
        # Optional: marker row
        try:
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                await session.execute(
                    text(
                        """
                        INSERT INTO submission_markers (id, form_id, response_id, lat, lon, country_code)
                        VALUES (:id, :form_id, :response_id, :lat, :lon, :country)
                        ON CONFLICT (id) DO NOTHING
                        """
                    ),
                    {"id": response_id, "form_id": form_id, "response_id": response_id, "lat": float(lat), "lon": float(lon), "country": country_code},
                )
        except Exception:
            pass
        # Optional: notification
        try:
            preview_text = ""
            for v in (answers or {}).values():
                if isinstance(v, str) and v.strip():
                    preview_text = v.strip()[:140]
                    break
            title = str(form_data.get("title") or "Form")
            await session.execute(
                text(
                    """
                    INSERT INTO notifications (id, user_id, title, message, type, data)
                    VALUES (:id, :user_id, :title, :message, :type, :data)
                    ON CONFLICT (id) DO NOTHING
                    """
                ),
                {"id": response_id, "user_id": owner_id, "title": title, "message": (preview_text or "New submission"), "type": "submission", "data": json.dumps({"formId": form_id, "responseId": response_id})},
            )
        except Exception:
            pass
        # Increment forms.submissions
        await session.execute(
            text("UPDATE forms SET submissions = COALESCE(submissions,0) + 1, updated_at = NOW() WHERE id = :form_id"),
            {"form_id": form_id},
        )
        await session.commit()
    
    # Build record object for integrations (Google Sheets, Airtable, Slack, etc.)
    record = {
        "responseId": response_id,
        "formId": form_id,
        "answers": answers,
        "submittedAt": submitted_at.isoformat() if submitted_at else datetime.utcnow().isoformat(),
        "clientIp": ip,
        "country": country_code,
        "lat": lat,
        "lon": lon,
        "userAgent": str(request.headers.get("user-agent") or ""),
    }
    if isinstance(signatures, dict) and signatures:
        record["signatures"] = signatures
    
    # Expose geo hints to client response (non-breaking add-ons)
    try:
        if country_code:
            resp["country"] = country_code  # type: ignore[index]
        if isinstance(lat, (int, float)):
            resp["lat"] = float(lat)  # type: ignore[index]
        if isinstance(lon, (int, float)):
            resp["lon"] = float(lon)  # type: ignore[index]
    except Exception:
        pass
    # Firestore mirroring removed (Neon is source of truth)
    # Update country analytics aggregation (file-based)
    try:
        if country_code:
            async with async_session_maker() as session:
                await _analytics_increment_country(session, form_id, country_code, submitted_at)
    except Exception:
        logger.exception("analytics: country increment failed form_id=%s", form_id)
    # Attempt Google Sheets append if syncing is enabled for this form
    try:
        # try import via package-aware path first
        try:
            from routers.google_sheets import try_append_submission_for_form  # type: ignore
        except Exception:
            from routers.google_sheets import try_append_submission_for_form  # type: ignore
        owner_id = str(form_data.get("user_id") or "").strip() or None
        if owner_id:
            try_append_submission_for_form(owner_id, form_id, record)
    except Exception:
        logger.exception("google_sheets sync append failed form_id=%s", form_id)
    # Attempt Airtable append if syncing is enabled for this form
    try:
        try:
            from routers.airtable import try_append_submission_for_form as _airtable_append  # type: ignore
        except Exception:
            from routers.airtable import try_append_submission_for_form as _airtable_append  # type: ignore
        owner_id = str(form_data.get("user_id") or "").strip() or None
        if owner_id:
            _airtable_append(owner_id, form_id, record)
    except Exception:
        logger.exception("airtable sync append failed form_id=%s", form_id)
    # Attempt Slack notification if configured
    try:
        try:
            from routers.slack import try_notify_slack_for_form  # type: ignore
        except Exception:
            from routers.slack import try_notify_slack_for_form  # type: ignore
        owner_id = str(form_data.get("user_id") or "").strip() or None
        if owner_id:
            try_notify_slack_for_form(owner_id, form_id, record)
    except Exception:
        logger.exception("slack notify failed form_id=%s", form_id)
    # Email notification to form owner (best-effort, using pre-fetched owner_email)
    try:
        if owner_email:
            await send_owner_notification(owner_email, form_id, form_data, record)
        else:
            logger.warning("Owner email not available for notification form_id=%s owner_id=%s", form_id, str(form_data.get("user_id") or ""))
    except Exception as e:
        logger.exception("owner email notify failed form_id=%s owner_email=%s error=%s", form_id, owner_email, str(e))
    # Server-side mirrors to Firestore for submissions, markers and notifications (no client writes)
    try:
        if _FS_AVAILABLE:
            fs = _fs.client()
            # Submissions collection: store minimal snapshot for dashboards/maps
            try:
                owner_id_safe = owner_id or ""
            except Exception:
                owner_id_safe = ""
            try:
                # Use responseId as document id for idempotency
                sub_ref = fs.collection("submissions").document(response_id)
                # Build preview text from first string-like answer
                preview_text = ""
                try:
                    for _k, _v in (answers or {}).items():
                        if isinstance(_v, str) and _v.strip():
                            preview_text = _v.strip()[:140]
                            break
                except Exception:
                    preview_text = ""
                sub_ref.set({
                    "formId": form_id,
                    "ownerId": owner_id_safe,
                    "responseId": response_id,
                    "submittedAt": _fs.SERVER_TIMESTAMP,
                    "country": country_code,
                    "lat": lat,
                    "lng": lon,
                    "values": answers,
                    "preview": preview_text,
                }, merge=True)
            except Exception:
                pass
            # Submissions markers: append marker entry for map rendering
            try:
                mr_ref = fs.collection("submissions_markers").document(form_id)
                markers_doc = mr_ref.get()
                markers = []
                try:
                    if markers_doc.exists:
                        data_doc = markers_doc.to_dict() or {}
                        if isinstance(data_doc.get("markers"), list):
                            markers = data_doc.get("markers")
                except Exception:
                    markers = []
                marker_entry = {
                    "id": response_id,
                    "position": [lat, lon] if (isinstance(lat, (int, float)) and isinstance(lon, (int, float))) else None,
                    "country": country_code,
                }
                # Avoid duplicates
                try:
                    if not any(isinstance(m, dict) and str(m.get("id")) == response_id for m in (markers or [])):
                        markers.append(marker_entry)
                except Exception:
                    markers.append(marker_entry)
                mr_ref.set({"markers": markers, "updatedAt": _fs.SERVER_TIMESTAMP}, merge=True)
            except Exception:
                pass
            # Creator notifications: notifications/{ownerId}/items/*
            try:
                if owner_id_safe:
                    items_ref = fs.collection("notifications").document(owner_id_safe).collection("items").document()
                    items_ref.set({
                        "formId": form_id,
                        "formTitle": str(form_data.get("title") or "Form"),
                        "preview": (preview_text if isinstance(preview_text, str) else ""),
                        "submittedAt": _fs.SERVER_TIMESTAMP,
                        "read": False,
                    }, merge=True)
            except Exception:
                pass
    except Exception:
        # Never fail submission on Firestore mirror errors
        pass

    # Include geo hints in response for client-side use without extra roundtrips
    try:
        if isinstance(lat, (int, float)):
            resp["lat"] = float(lat)
        if isinstance(lon, (int, float)):
            resp["lon"] = float(lon)
        if country_code:
            resp["country"] = country_code
    except Exception:
        pass

    # Optionally return responseId to the client
    resp["responseId"] = response_id  # type: ignore

    # Increment monthly usage for Free plans
    try:
        path = _form_path(form_id)
        if os.path.exists(path):
            _fd = _read_json(path)
            _owner = str(_fd.get("userId") or "").strip() or None
            if _owner and not _is_pro_plan(_owner):
                _inc_month_count(_owner, _month_key(), 1)
    except Exception:
        pass

    # Auto-reply thank you email to submitter (if configured)
    try:
        owner_id_for_email = str(form_data.get("user_id") or "").strip() or None
        await send_auto_reply_email(form_data, payload, owner_id_for_email)
    except Exception as e:
        logger.exception("Auto-reply send failed form_id=%s: %s", form_id, str(e))

    logger.info("form submitted id=%s response_id=%s", form_id, resp.get("responseId"))
    return resp


# -----------------------------
# Submissions listing & retrieval (Neon-backed)
# -----------------------------

@router.get("/forms/{form_id}/responses")
@limiter.limit("120/minute")
async def list_form_responses(form_id: str, request: Request, limit: int = 50, offset: int = 0, from_: Optional[str] = Query(default=None, alias="from"), to: Optional[str] = Query(default=None)):
    """List submissions for a form owned by the authenticated user.
    Returns a paginated list ordered by submitted_at DESC.
    Response: { items: [...], total: number, limit, offset }
    """
    # Auth
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Clamp pagination
    try:
        limit = max(1, min(200, int(limit)))
    except Exception:
        limit = 50
    try:
        offset = max(0, int(offset))
    except Exception:
        offset = 0

    async with async_session_maker() as session:
        # Ownership check
        res = await session.execute(
            text("SELECT user_id FROM forms WHERE id = :fid LIMIT 1"),
            {"fid": form_id},
        )
        row = res.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Form not found")
        form_user = (row.get("user_id") or "").strip()
        if uid not in (form_user,):
            raise HTTPException(status_code=403, detail="Forbidden")

        # Total count with optional date filters
        # Parse 'from' and 'to' query params (ISO8601). Accepts 'Z' timezone.
        th_from = None
        th_to = None
        try:
            if from_:
                s = str(from_).strip()
                if s.endswith("Z"):
                    s = s[:-1] + "+00:00"
                th_from = datetime.fromisoformat(s)
        except Exception:
            th_from = None
        try:
            if to:
                s = str(to).strip()
                if s.endswith("Z"):
                    s = s[:-1] + "+00:00"
                th_to = datetime.fromisoformat(s)
        except Exception:
            th_to = None

        if th_from and th_to:
            res_total = await session.execute(
                text("SELECT COUNT(*) AS cnt FROM submissions WHERE form_id = :fid AND submitted_at BETWEEN :f AND :t"),
                {"fid": form_id, "f": th_from, "t": th_to},
            )
        elif th_from:
            res_total = await session.execute(
                text("SELECT COUNT(*) AS cnt FROM submissions WHERE form_id = :fid AND submitted_at >= :f"),
                {"fid": form_id, "f": th_from},
            )
        elif th_to:
            res_total = await session.execute(
                text("SELECT COUNT(*) AS cnt FROM submissions WHERE form_id = :fid AND submitted_at <= :t"),
                {"fid": form_id, "t": th_to},
            )
        else:
            res_total = await session.execute(
                text("SELECT COUNT(*) AS cnt FROM submissions WHERE form_id = :fid"),
                {"fid": form_id},
            )
        total = int((res_total.mappings().first() or {}).get("cnt") or 0)

        # Page items
        base_sql = """
            SELECT id, form_id, form_owner_id, data, metadata,
                   ip_address, country_code, user_agent, submitted_at
            FROM submissions
            WHERE form_id = :fid
        """
        cond = ""
        params = {"fid": form_id, "lim": limit, "off": offset}
        if th_from and th_to:
            cond = " AND submitted_at BETWEEN :f AND :t"
            params.update({"f": th_from, "t": th_to})
        elif th_from:
            cond = " AND submitted_at >= :f"
            params.update({"f": th_from})
        elif th_to:
            cond = " AND submitted_at <= :t"
            params.update({"t": th_to})
        sql_items = text(base_sql + cond + " ORDER BY submitted_at DESC LIMIT :lim OFFSET :off").bindparams(
            bindparam("lim", type_=Integer),
            bindparam("off", type_=Integer),
        )
        res_items = await session.execute(sql_items, params)
        raw_items = [dict(r) for r in res_items.mappings().all()]
        
        # Parse JSONB fields and format for client
        items = []
        for r in raw_items:
            item = {
                "id": r.get("id"),
                "formId": r.get("form_id"),
                "submittedAt": r.get("submitted_at").isoformat() if r.get("submitted_at") else None,
                "clientIp": r.get("ip_address"),
                "country": r.get("country_code"),
                "userAgent": r.get("user_agent"),
            }
            # Parse data field (encrypted submission data)
            try:
                data = r.get("data")
                # Data is stored encrypted, decrypt it first
                if isinstance(data, str):
                    try:
                        # Decrypt the encrypted data
                        decrypted = decrypt_submission_data(data)
                        if isinstance(decrypted, dict):
                            item["answers"] = decrypted
                        else:
                            # If decrypted data is a string, try parsing as JSON
                            item["answers"] = json.loads(decrypted) if isinstance(decrypted, str) else {}
                    except Exception as decrypt_err:
                        logger.error(f"Decryption failed for submission {r.get('id')}: {decrypt_err}")
                        item["answers"] = {}
                elif isinstance(data, dict):
                    item["answers"] = data
                else:
                    item["answers"] = {}
            except Exception:
                item["answers"] = {}
            
            # Parse metadata field (JSONB)
            try:
                metadata = r.get("metadata")
                if isinstance(metadata, str):
                    meta = json.loads(metadata)
                elif isinstance(metadata, dict):
                    meta = metadata
                else:
                    meta = {}
                # Expose useful metadata fields
                if meta.get("lat"):
                    item["lat"] = meta.get("lat")
                if meta.get("lon"):
                    item["lon"] = meta.get("lon")
                if meta.get("signatures"):
                    item["signatures"] = meta.get("signatures")
            except Exception:
                pass
            
            items.append(item)

    # Back-compat: some clients expect 'responses'
    return {"items": items, "responses": items, "total": total, "limit": limit, "offset": offset}


@router.get("/forms/{form_id}/responses/{response_id}")
@limiter.limit("240/minute")
async def get_form_response(form_id: str, response_id: str, request: Request):
    """Get a single submission for a form owned by the authenticated user."""
    try:
        uid = _verify_firebase_uid(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")

    async with async_session_maker() as session:
        # Ownership check
        res = await session.execute(
            text("SELECT user_id FROM forms WHERE id = :fid LIMIT 1"),
            {"fid": form_id},
        )
        row = res.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Form not found")
        form_user = (row.get("user_id") or "").strip()
        if uid not in (form_user,):
            raise HTTPException(status_code=403, detail="Forbidden")

        res_sub = await session.execute(
            text(
                """
                SELECT id, form_id, form_owner_id, data, metadata,
                       ip_address, country_code, user_agent, submitted_at
                FROM submissions
                WHERE id = :rid AND form_id = :fid
                LIMIT 1
                """
            ),
            {"rid": response_id, "fid": form_id},
        )
        sub = res_sub.mappings().first()
        if not sub:
            raise HTTPException(status_code=404, detail="Response not found")
        
        # Parse JSONB fields to proper format
        r = dict(sub)
        item = {
            "id": r.get("id"),
            "formId": r.get("form_id"),
            "submittedAt": r.get("submitted_at").isoformat() if r.get("submitted_at") else None,
            "clientIp": r.get("ip_address"),
            "country": r.get("country_code"),
            "userAgent": r.get("user_agent"),
        }
        # Parse data field (encrypted submission data)
        try:
            data = r.get("data")
            # Data is stored encrypted, decrypt it first
            if isinstance(data, str):
                try:
                    # Decrypt the encrypted data
                    decrypted = decrypt_submission_data(data)
                    if isinstance(decrypted, dict):
                        item["answers"] = decrypted
                    else:
                        # If decrypted data is a string, try parsing as JSON
                        item["answers"] = json.loads(decrypted) if isinstance(decrypted, str) else {}
                except Exception as decrypt_err:
                    logger.error(f"Decryption failed for submission {r.get('id')}: {decrypt_err}")
                    item["answers"] = {}
            elif isinstance(data, dict):
                item["answers"] = data
            else:
                item["answers"] = {}
        except Exception:
            item["answers"] = {}
        
        # Parse metadata field (JSONB)
        try:
            metadata = r.get("metadata")
            if isinstance(metadata, str):
                meta = json.loads(metadata)
            elif isinstance(metadata, dict):
                meta = metadata
            else:
                meta = {}
            # Expose useful metadata fields
            if meta.get("lat"):
                item["lat"] = meta.get("lat")
            if meta.get("lon"):
                item["lon"] = meta.get("lon")
            if meta.get("signatures"):
                item["signatures"] = meta.get("signatures")
        except Exception:
            pass
        
        # Back-compat alias 'responses' with single-element array
        return {"response": item, "responses": [item]}

# Custom domain endpoints have been moved to routers/custom_domain.py


@router.post("/admin/certificates/renew-now")
async def renew_now():
    """No-op: Caddy handles renewals automatically."""
    return {"ok": True, "mode": "caddy", "message": "Renewal handled automatically by Caddy."}


@router.get("/admin/certificates/renew-health")
async def renew_health():
    """Simple health check for Caddy mode."""
    return {"enabled": True, "mode": "caddy", "message": "Caddy auto-renews certificates internally."}

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

    @router.get("/forms/{form_id}/responses")
    async def list_responses(
        form_id: str,
        limit: int = 100,
        offset: int = 0,
        from_ts: Optional[str] = Query(default=None, alias="from", description="ISO datetime lower bound (inclusive)"),
        to_ts: Optional[str] = Query(default=None, alias="to", description="ISO datetime upper bound (inclusive)"),
    ):
        """
        List stored responses for a form from Neon. Results are sorted by submittedAt descending.
        Optional query params:
          - from (ISO datetime): include responses with submittedAt >= this
          - to (ISO datetime): include responses with submittedAt <= this
        """
        # Build filter bounds on submitted_at
        start_dt = _to_date(from_ts) if from_ts else None
        end_dt = _to_date(to_ts) if to_ts else None
        async with async_session_maker() as session:
            # Total count with filters
            where_clauses = ["form_id = :fid"]
            params: Dict[str, Any] = {"fid": form_id}
            if start_dt:
                where_clauses.append("submitted_at >= :start")
                params["start"] = start_dt
            if end_dt:
                where_clauses.append("submitted_at <= :end")
                params["end"] = end_dt
            where_sql = " AND ".join(where_clauses)
            count_sql = f"SELECT COUNT(*) AS cnt FROM submissions WHERE {where_sql}"
            res = await session.execute(text(count_sql), params)
            total = int((res.mappings().first() or {}).get("cnt") or 0)

            # Page of responses
            list_sql = f"""
                SELECT id, form_id, form_owner_id, data, metadata,
                       ip_address, country_code, user_agent, submitted_at
                FROM submissions
                WHERE {where_sql}
                ORDER BY submitted_at DESC
                LIMIT :limit OFFSET :offset
            """
            params_page = dict(params)
            params_page.update({"limit": max(0, int(limit)), "offset": max(0, int(offset))})
            res = await session.execute(text(list_sql), params_page)
            rows = [dict(r) for r in res.mappings().all()]
            # Normalize to previous response object shape where possible
            items: List[Dict] = []
            for r in rows:
                try:
                    answers = r.get("data")
                    if isinstance(answers, str):
                        try:
                            answers = json.loads(answers)
                        except Exception:
                            answers = {}
                    meta = r.get("metadata") or {}
                    if isinstance(meta, str):
                        try:
                            meta = json.loads(meta)
                        except Exception:
                            meta = {}
                    items.append({
                        "id": r.get("id"),
                        "formId": r.get("form_id"),
                        "answers": answers or {},
                        "submittedAt": (r.get("submitted_at") or ""),
                        "clientIp": r.get("ip_address"),
                        "userAgent": r.get("user_agent"),
                        "metadata": meta,
                    })
                except Exception:
                    continue
            return {"count": total, "responses": items}

    @router.post("/forms/{form_id}/responses/delete-batch")
    async def delete_responses_batch(form_id: str, request: Request, payload: Dict = None):
        """
        Delete multiple stored responses for a form by responseId.
        Auth required: Firebase ID token in Authorization: Bearer <token> header. Only the form owner can delete.
        Body: { "ids": ["<responseId>", ...] }
        Response: { success: true, deleted: <count>, idsDeleted: [...], idsFailed: [...] }
        """
        # Auth: Firebase token -> uid
        try:
            uid = _verify_firebase_uid(request)
        except Exception:
            raise HTTPException(status_code=401, detail="Unauthorized")

        ids_raw = (payload or {}).get("ids") or []
        ids: List[str] = []
    #   - from (ISO datetime): include days >= this date
    #   - to (ISO datetime): include days <= this date
    # When no range is provided, returns the all-time totals.

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


async def _ensure_dns_integrations_table(session) -> None:
    try:
        await session.execute(text(
            """
            CREATE TABLE IF NOT EXISTS dns_integrations (
              uid TEXT PRIMARY KEY,
              cloudflare_token TEXT,
              updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            """
        ))
    except Exception:
        # best-effort
        pass

async def _store_cloudflare_token(uid: str, token: str) -> None:
    # Neon storage
    try:
        async with async_session_maker() as session:
            await _ensure_dns_integrations_table(session)
            await session.execute(
                text(
                    """
                    INSERT INTO dns_integrations (uid, cloudflare_token, updated_at)
                    VALUES (:uid, :tok, NOW())
                    ON CONFLICT (uid) DO UPDATE SET
                      cloudflare_token = EXCLUDED.cloudflare_token,
                      updated_at = NOW()
                    """
                ),
                {"uid": uid, "tok": token},
            )
            await session.commit()
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to store DNS credentials")


async def _get_cloudflare_token(uid: str) -> str:
    # Neon only
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                text("SELECT cloudflare_token FROM dns_integrations WHERE uid = :uid LIMIT 1"),
                {"uid": uid},
            )
            row = res.mappings().first()
            token = (row or {}).get("cloudflare_token")
            token = (token or "").strip() if isinstance(token, str) else ""
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
    # Store Cloudflare API token for the current authenticated user.
    # Body: { apiToken: string }
    uid = _verify_firebase_uid(request)
    if not isinstance(payload, dict) or not str(payload.get("apiToken") or "").strip():
        raise HTTPException(status_code=400, detail="Missing apiToken")
    token = str(payload.get("apiToken")).strip()
    await _store_cloudflare_token(uid, token)
    return {"success": True}


@router.get("/dns/cloudflare/zones")
async def cloudflare_list_zones(request: Request):
    # List Cloudflare zones for the connected account.
    uid = _verify_firebase_uid(request)
    token = await _get_cloudflare_token(uid)
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
    # Create a DNS record in a Cloudflare zone.
    # Body: { type: "CNAME"|"TXT"|..., name: string, content: string, ttl?: number, proxied?: bool }
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
    # Automatically connect a custom domain for a form using Cloudflare.
    # Body: { formId: string, zoneId: string, subdomain: string }
    # Steps:
    # - Create CNAME record: subdomain.zone -> CUSTOM_DOMAIN_TARGET
    # - Verify domain in builder store
    # - Write Cloudflare credentials ini for DNS DNS-01 challenge
    # - Issue certificate via DNS challenge or fall back to on-demand TLS

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
