from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Literal
from datetime import datetime
import os
import json
import uuid

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


def _resolve_geoip_db_path() -> str:
    """Resolve a usable .mmdb path.
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

# Storage
BACKING_DIR = os.path.join(os.getcwd(), "data", "forms")
os.makedirs(BACKING_DIR, exist_ok=True)


def _form_path(form_id: str) -> str:
    return os.path.join(BACKING_DIR, f"{form_id}.json")


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
    textColor: str = "#111827"
    inputBgColor: str = "#ffffff"
    inputTextColor: str = "#111827"
    inputBorderColor: str = "#d1d5db"
    inputBorderRadius: int = 8


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
    preventDuplicateByUID: bool = False
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
    # Normalize restrictedCountries to upper-case ISO codes
    data["restrictedCountries"] = _normalize_country_list(data.get("restrictedCountries") or [])
    data["id"] = form_id
    data["createdAt"] = now
    data["updatedAt"] = now
    _write_json(_form_path(form_id), data)

    embed_url = f"/embed/{form_id}"
    iframe_snippet = f'<iframe src="{embed_url}" width="100%" height="600" frameborder="0"></iframe>'
    return {"id": form_id, "embedUrl": embed_url, "iframeSnippet": iframe_snippet}


@router.get("/forms/{form_id}")
async def get_form(form_id: str):
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
    # Normalize restrictedCountries to upper-case ISO codes
    data["restrictedCountries"] = _normalize_country_list(data.get("restrictedCountries") or [])
    data["id"] = form_id
    prev = _read_json(path)
    data["createdAt"] = prev.get("createdAt")  # preserve original
    data["updatedAt"] = datetime.utcnow().isoformat()

    _write_json(path, data)

    embed_url = f"/embed/{form_id}"
    iframe_snippet = f'<iframe src="{embed_url}" width="100%" height="600" frameborder="0"></iframe>'
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
    return {"success": True}


@router.get("/forms/{form_id}/embed")
async def get_embed_snippet(form_id: str):
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")
    embed_url = f"/embed/{form_id}"
    iframe_snippet = f'<iframe src="{embed_url}" width="100%" height="600" frameborder="0"></iframe>'
    return {"id": form_id, "embedUrl": embed_url, "iframeSnippet": iframe_snippet}


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
        return {"allowed": True, "country": None}

    ip = _client_ip(request)
    _, country = _country_from_ip(ip)

    # If we cannot determine country (no DB or IP), allow by default
    if not country:
        return {"allowed": True, "country": None}

    if country in restricted:
        # Block with required message
        raise HTTPException(status_code=403, detail="Your IP location is restricted from submitting the form, We're sorry about that")

    return {"allowed": True, "country": country}


@router.post("/forms/{form_id}/submit")
async def submit_form(form_id: str, request: Request, payload: Dict = None):
    """Simple submission endpoint that enforces country restrictions.
    On success returns {success: True, message, redirectUrl?}.
    """
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Form not found")

    form_data = _read_json(path)

    # Geo restriction enforcement
    restricted = _normalize_country_list(form_data.get("restrictedCountries") or [])
    if restricted:
        ip = _client_ip(request)
        _, country = _country_from_ip(ip)
        if country and country in restricted:
            raise HTTPException(status_code=403, detail="Your IP location is restricted from submitting the form, We're sorry about that")

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
    resp: Dict[str, Optional[str] | bool] = {
        "success": True,
        "message": form_data.get("thankYouMessage"),
    }
    redir = form_data.get("redirect") or {}
    if redir.get("enabled") and redir.get("url"):
        resp["redirectUrl"] = redir.get("url")

    return resp
