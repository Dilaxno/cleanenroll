from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import re
import json
from urllib.parse import urlparse

# Optional imports with fallbacks
try:
    from utils.limiter import limiter  # type: ignore
except Exception:
    try:
        from utils.limiter import limiter  # type: ignore
    except Exception:  # pragma: no cover
        class _Dummy:
            def limit(self, *_args, **_kwargs):
                def deco(fn):
                    return fn
                return deco
        limiter = _Dummy()  # type: ignore

try:
    import tldextract  # type: ignore
    _TLDX_AVAILABLE = True
except Exception:
    tldextract = None  # type: ignore
    _TLDX_AVAILABLE = False

try:
    import urllib.request as _urlreq
    import urllib.error as _urlerr
except Exception:  # pragma: no cover
    _urlreq = None  # type: ignore
    _urlerr = None  # type: ignore

# Optional dnspython resolver for MX checks
try:
    import dns.resolver as _dns_resolver  # type: ignore
    _DNSPY_AVAILABLE = True
except Exception:
    _dns_resolver = None  # type: ignore
    _DNSPY_AVAILABLE = False

router = APIRouter()

# Allowlist of commonly safe / business / legitimate TLDs
SAFE_TLDS = {
    # Commercial & General
    "com", "net", "org", "co", "biz", "info",
    # Tech / SaaS / Startup
    "io", "app", "dev", "me", "ai", "cloud", "tech", "software",
    # Geography & Corporate
    "us", "uk", "ca", "de", "eu", "in", "jp", "fr", "es",
    # Education / Government
    "edu", "gov", "ac", "int",
    # Misc Common
    "store", "shop", "blog", "media",
}

# Denylist of known spammy / abused / scam-heavy TLDs
SPAMMY_TLDS = {
    "xyz", "top", "click", "work", "loan", "zip", "men",
    "surf", "party", "gq", "cf", "ml", "tk", "cam",
    "quest", "accountant", "beauty", "monster", "win",
    "date", "racing", "download", "buzz", "fit", "review",
    "space", "link", "club", "cyou",
}

# Strict syntax pattern:
# - Must start with https://
# - Host: one or more labels of letters/digits/hyphen ending with a safe TLD
# - Optional path/query/fragment allowed afterward
SAFE_TLD_PATTERN = "|".join(sorted(SAFE_TLDS))
STRICT_HTTPS_REGEX = re.compile(rf"^https://([A-Za-z0-9-]+\.)+({SAFE_TLD_PATTERN})(/|$)", re.IGNORECASE)

# Quick "too random" label heuristic: long alnum label w/ low vowel ratio and possibly digits
RANDOM_LABEL_RE = re.compile(r"^[a-z0-9]{8,}$", re.IGNORECASE)

class UrlCheckRequest(BaseModel):
    url: str

class UrlCheckResponse(BaseModel):
    input: str
    syntax_valid: bool
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    tld: Optional[str] = None
    has_mx: Optional[bool] = None
    mx_hosts: Optional[list[str]] = None
    allowed: bool
    blocked: bool
    reasons: list[str] = []
    safe_browsing: Optional[Dict[str, Any]] = None
    risk_score: int = 0  # 0..100, block when >= 50


def _is_randomish_label(label: str) -> bool:
    try:
        s = (label or "").lower()
        if not RANDOM_LABEL_RE.fullmatch(s):
            return False
        # Heuristic: low vowel ratio or contains digits suggests auto-generated
        vowels = sum(1 for ch in s if ch in "aeiou")
        ratio = vowels / max(1, len(s))
        has_digit = any(ch.isdigit() for ch in s)
        return (ratio < 0.25) or has_digit
    except Exception:
        return False


def _basic_syntax_check(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    if not STRICT_HTTPS_REGEX.match(url.strip()):
        return False
    return True


def _extract_parts(url: str) -> tuple[str | None, str | None, str | None]:
    try:
        parsed = urlparse(url)
        proto = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").strip().lower().strip(".")
        tld = None
        if host:
            if _TLDX_AVAILABLE:
                ext = tldextract.extract(host)
                tld = (ext.suffix or "").lower().strip(".")
            else:
                if "." in host:
                    tld = host.rsplit(".", 1)[-1].lower()
        return proto, host, tld
    except Exception:
        return None, None, None


def _gibberish_check(host: str) -> bool:
    """Return True if host looks random/gibberish (should be blocked)."""
    try:
        if not host:
            return True
        # If tldextract available, use SLD; else use the left-most label
        if _TLDX_AVAILABLE:
            ext = tldextract.extract(host)
            sld = (ext.domain or "").lower()
        else:
            sld = host.split(".")[0].lower()
        if not sld:
            return True
        # Block long alnum labels with low vowel ratio or digits
        if _is_randomish_label(sld):
            return True
        return False
    except Exception:
        return False


# MX lookup helper using dnspython
def _mx_lookup(domain: str) -> list[str]:
    if not _DNSPY_AVAILABLE or not domain:
        return []
    try:
        answers = _dns_resolver.resolve(domain, "MX", lifetime=2.0)  # type: ignore
        hosts: list[str] = []
        for rdata in answers:  # type: ignore
            try:
                host = str(getattr(rdata, "exchange", "") or "").rstrip(".")
                if host:
                    hosts.append(host)
            except Exception:
                continue
        hosts.sort()
        return hosts
    except Exception:
        return []

def _google_safe_browsing_check(url: str) -> dict:
    """Query Google Safe Browsing v4 to check if URL is malicious.
    Returns a dict: {enabled: bool, malicious: bool, matches: list}
    Fails open (enabled True with malicious False) when API fails.
    """
    api_key = (os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("SAFE_BROWSING_API_KEY") or "").strip()
    if not api_key:
        return {"enabled": False, "malicious": False, "matches": []}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        body = {
            "client": {"clientId": "cleanenroll", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        data = json.dumps(body).encode("utf-8")
        req = _urlreq.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
        with _urlreq.urlopen(req, timeout=6) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            try:
                payload = json.loads(raw)
            except Exception:
                payload = {}
        matches = payload.get("matches", []) if isinstance(payload, dict) else []
        return {"enabled": True, "malicious": bool(matches), "matches": matches or []}
    except Exception:
        # Fail open
        return {"enabled": True, "malicious": False, "matches": []}


@router.options("/api/validate-url")
@router.options("/api/validate-url/")
async def validate_url_options():
    return PlainTextResponse("", status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })


@router.get("/api/validate-url")
@router.get("/api/validate-url/")
@limiter.limit("30/minute")
async def validate_url_get(request: Request, url: str):
    return await _validate_url_impl(url)


@router.get("/api/builder/url/scan")
@router.get("/api/builder/url/scan/")
@limiter.limit("30/minute")
async def url_scan_get(request: Request, url: str):
    """Alias endpoint for URL scanning called by frontend."""
    return await _validate_url_impl(url)


@router.post("/api/validate-url")
@router.post("/api/validate-url/")
@limiter.limit("30/minute")
async def validate_url_post(request: Request, req: UrlCheckRequest):
    return await _validate_url_impl(req.url)


async def _validate_url_impl(url: str):
    raw = (url or "").strip()
    res: Dict[str, Any] = {
        "input": raw,
        "syntax_valid": False,
        "protocol": None,
        "hostname": None,
        "tld": None,
        "has_mx": None,
        "mx_hosts": [],
        "allowed": False,
        "blocked": True,
        "reasons": [],
        "safe_browsing": None,
        "risk_score": 0,
    }

    risk = 0

    if not raw:
        res["reasons"].append("URL is required")
        risk = max(risk, 100)
        res["risk_score"] = risk
        res["allowed"] = False
        res["blocked"] = True
        return JSONResponse(res)

    # Basic regex syntax validation
    if not _basic_syntax_check(raw):
        res["reasons"].append("URL must start with https:// and use a safe TLD")
        risk = max(risk, 80)
        res["risk_score"] = risk
        res["allowed"] = False
        res["blocked"] = True
        return JSONResponse(res)

    proto, host, tld = _extract_parts(raw)
    res["protocol"], res["hostname"], res["tld"] = proto, host, tld

    if proto != "https":
        res["reasons"].append("Only https:// URLs are allowed")
        risk = max(risk, 60)
        res["risk_score"] = risk
        res["allowed"] = False
        res["blocked"] = True
        return JSONResponse(res)

    # TLD policy: allowlist and denylist
    if not tld or tld not in SAFE_TLDS:
        res["reasons"].append("TLD is not in the allowed list")
        risk = max(risk, 60)
        res["risk_score"] = risk
        res["allowed"] = False
        res["blocked"] = True
        return JSONResponse(res)

    if tld in SPAMMY_TLDS:
        res["reasons"].append("Disallowed domain ending (spammy TLD)")
        risk = max(risk, 80)
        res["risk_score"] = risk
        res["allowed"] = False
        res["blocked"] = True
        return JSONResponse(res)

    # Random/gibberish SLD detection
    if _gibberish_check(host or ""):
        res["reasons"].append("Suspicious domain pattern")
        risk = max(risk, 65)
        res["risk_score"] = risk
        res["allowed"] = False
        res["blocked"] = True
        return JSONResponse(res)

    # MX check on registrable domain using dnspython (best-effort)
    mx_domain = host or ""
    try:
        if _TLDX_AVAILABLE and host:
            ext = tldextract.extract(host)
            reg = (getattr(ext, "registered_domain", "") or "").strip().lower()
            if reg:
                mx_domain = reg
            elif getattr(ext, "domain", None) and getattr(ext, "suffix", None):
                mx_domain = f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass

    mx_hosts = _mx_lookup(mx_domain) if mx_domain else []
    res["mx_hosts"] = mx_hosts
    res["has_mx"] = (len(mx_hosts) > 0) if _DNSPY_AVAILABLE else None
    if _DNSPY_AVAILABLE and not mx_hosts:
        res["reasons"].append("No MX records found for domain")
        risk = max(risk, 55)
        res["risk_score"] = risk
        # Enforce risk gate: block when score >= 50
        res["allowed"] = False
        res["blocked"] = True
        return JSONResponse(res)

    # Passed syntax checks; call Google Safe Browsing for final verdict
    sb = _google_safe_browsing_check(raw)
    res["safe_browsing"] = sb

    if sb.get("malicious"):
        res["reasons"].append("URL flagged by Safe Browsing")
        risk = max(risk, 100)
        res["risk_score"] = risk
        res["syntax_valid"] = True
        res["allowed"] = False
        res["blocked"] = True
        return JSONResponse(res)

    # All checks passed so far
    res["syntax_valid"] = True

    # Apply final risk gate (>= 50 blocks form submission)
    res["risk_score"] = risk
    if risk >= 50:
        res["allowed"] = False
        res["blocked"] = True
    else:
        res["allowed"] = True
        res["blocked"] = False

    return JSONResponse(res)
