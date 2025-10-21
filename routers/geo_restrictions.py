from fastapi import APIRouter, HTTPException, Request
from typing import List, Optional, Tuple
import logging
import os
import json
import urllib.parse
import urllib.request
from sqlalchemy import text

# Database session
from db.database import async_session_maker

# GeoIP providers
try:
    from ip2geotools.databases.noncommercial import DbIpCity  # type: ignore
    _DBIPCITY_AVAILABLE = True
except Exception:
    DbIpCity = None  # type: ignore
    _DBIPCITY_AVAILABLE = False

# MaxMind GeoIP2 database support
try:
    import maxminddb
    _MAXMIND_AVAILABLE = True
except Exception:
    maxminddb = None  # type: ignore
    _MAXMIND_AVAILABLE = False

GEOAPIFY_API_KEY = os.getenv("GEOAPIFY_API_KEY") or ""
IPINFO_API_TOKEN = os.getenv("IPINFO_API_TOKEN") or ""
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH") or ""

_GEOAPIFY_AVAILABLE = bool(GEOAPIFY_API_KEY)
_IPINFO_AVAILABLE = bool(IPINFO_API_TOKEN)
_GEOIP2_AVAILABLE = bool(_MAXMIND_AVAILABLE and GEOIP_DB_PATH)
_GEO_LOOKUP_AVAILABLE = bool(_GEOIP2_AVAILABLE or _IPINFO_AVAILABLE or _GEOAPIFY_AVAILABLE or _DBIPCITY_AVAILABLE)

# Logger
logger = logging.getLogger("backend.geo_restrictions")

# Log geo lookup availability at import time
try:
    logger.info("geo: providers geoip2=%s (path=%s) ipinfo=%s geoapify=%s dbipcity=%s", _GEOIP2_AVAILABLE, GEOIP_DB_PATH or 'none', _IPINFO_AVAILABLE, _GEOAPIFY_AVAILABLE, _DBIPCITY_AVAILABLE)
    if not _GEO_LOOKUP_AVAILABLE:
        logger.warning("geo: no geolocation provider available; country/lat/lon enrichment disabled")
except Exception:
    pass

router = APIRouter()

# -----------------------------
# Geo helpers
# -----------------------------

def _normalize_country_list(codes: Optional[List[str]]) -> List[str]:
    """Normalize a list of country codes to uppercase."""
    if not codes:
        return []
    return [str(c).strip().upper() for c in codes if str(c).strip()]


def _client_ip(request: Request) -> str:
    """Extract client IP from request, respecting X-Forwarded-For."""
    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if xff:
        # Take first IP
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    return request.client.host if request.client else ""


def _country_from_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """Get country ISO-2 code from IP address.
    Returns (success, country_code).
    """
    if not ip:
        logger.debug("geo: _country_from_ip skipped ip=%s", ip)
        return False, None
    
    # Skip localhost/private IPs
    if ip in ('127.0.0.1', 'localhost') or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
        logger.debug("geo: _country_from_ip skipped private ip=%s", ip)
        return False, None
    
    # Primary: GeoIP2/MaxMind local database (fastest, no API calls)
    if _GEOIP2_AVAILABLE and maxminddb:
        try:
            # Handle tar.gz path - extract to get .mmdb file
            db_path = GEOIP_DB_PATH
            if db_path.endswith('.tar.gz'):
                # Look for extracted .mmdb file in same directory or common locations
                import pathlib
                base_dir = pathlib.Path(db_path).parent
                # Try common paths
                possible_paths = [
                    base_dir / 'GeoLite2-City.mmdb',
                    pathlib.Path('data/geoip/GeoLite2-City.mmdb'),
                    pathlib.Path('/home/deployer/cleanenroll/data/geoip/GeoLite2-City.mmdb'),
                ]
                for path in possible_paths:
                    if path.exists():
                        db_path = str(path)
                        break
            
            with maxminddb.open_database(db_path) as reader:
                result = reader.get(ip)
                if result and 'country' in result:
                    country_code = result['country'].get('iso_code')
                    if country_code:
                        cc = str(country_code).strip().upper()
                        logger.debug("geo: _country_from_ip (geoip2) ip=%s country=%s", ip, cc)
                        return True, cc
        except Exception as e:
            logger.warning("geo: _country_from_ip geoip2 failed ip=%s err=%s", ip, e)
            # fallthrough to fallback
    
    # Fallback 1: IPinfo.io
    if _IPINFO_AVAILABLE:
        try:
            url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_TOKEN}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "CleanEnroll/1.0 (+https://cleanenroll.com)",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=6) as resp:  # type: ignore
                raw = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(raw) if raw else {}
            # IPinfo returns 'country' field with ISO-2 code
            country = data.get("country") or data.get("country_code")
            cc = (str(country or "").strip().upper() or None)
            logger.debug("geo: _country_from_ip (ipinfo) ip=%s country=%s", ip, cc)
            return (cc is not None), cc
        except Exception as e:
            logger.warning("geo: _country_from_ip ipinfo failed ip=%s err=%s", ip, e)
            # fallthrough to fallback
    
    # Fallback 1: Geoapify when configured
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
    
    # Fallback 2: DbIpCity when importable
    if DbIpCity is not None:
        try:
            result = DbIpCity.get(ip, api_key="free")  # type: ignore
            code = (getattr(result, "country", None) or "").upper()
            logger.debug("geo: _country_from_ip (dbipcity) ip=%s country=%s", ip, code or None)
            return True, code or None
        except Exception as e:
            logger.warning("geo: _country_from_ip dbipcity failed ip=%s err=%s", ip, e)
    return False, None


# -----------------------------
# Endpoints
# -----------------------------

@router.get("/builder/forms/{form_id}/geo-check")
async def check_geo_restriction(form_id: str, request: Request):
    """Check if the visitor's country is allowed to view/submit the form.
    Returns 200 if allowed, 403 if restricted.
    """
    try:
        # Load form from Neon
        async with async_session_maker() as session:
            res = await session.execute(
                text("SELECT * FROM forms WHERE id = :fid LIMIT 1"),
                {"fid": form_id},
            )
            row = res.mappings().first()
        
        if not row:
            raise HTTPException(status_code=404, detail="Form not found")
        
        form_data = dict(row)
        
        # Check if user is pro (geo restrictions are pro feature)
        user_id = str(form_data.get("user_id") or "").strip() or None
        is_pro = False
        if user_id:
            try:
                async with async_session_maker() as session:
                    user_res = await session.execute(
                        text("SELECT plan FROM users WHERE uid = :uid LIMIT 1"),
                        {"uid": user_id},
                    )
                    user_row = user_res.mappings().first()
                    if user_row:
                        plan = str(user_row.get("plan") or "").strip().lower()
                        is_pro = plan in ("pro", "premium", "enterprise", "business")
            except Exception:
                pass
        
        # Get client IP and check restrictions
        ip = _client_ip(request)
        # Database uses snake_case (restricted_countries, allowed_countries)
        allowed = _normalize_country_list(form_data.get("allowed_countries") or []) if is_pro else []
        restricted = _normalize_country_list(form_data.get("restricted_countries") or []) if is_pro else []
        
        if allowed or restricted:
            detected, country = _country_from_ip(ip)
            
            # If country detection failed and restrictions are enabled, block (fail closed for security)
            if not detected or not country:
                logger.warning("geo: country detection failed for ip=%s in preview, blocking due to active restrictions", ip)
                raise HTTPException(
                    status_code=403,
                    detail="We're sorry, but submissions from your country are currently restricted due to regional limitations."
                )
            
            # Check allowed countries (whitelist)
            if allowed and country not in allowed:
                logger.info("geo: blocked preview for %s (not in allowed list)", country)
                raise HTTPException(
                    status_code=403,
                    detail="We're sorry, but submissions from your country are currently restricted due to regional limitations."
                )
            
            # Check restricted countries (blacklist)
            if restricted and country in restricted:
                logger.info("geo: blocked preview for %s (in restricted list)", country)
                raise HTTPException(
                    status_code=403,
                    detail="We're sorry, but submissions from your country are currently restricted due to regional limitations."
                )
        
        return {"ok": True, "message": "Access allowed"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("geo-check failed form_id=%s", form_id)
        # Don't block on geo-check errors
        return {"ok": True, "message": "Access allowed (check bypassed due to error)"}
