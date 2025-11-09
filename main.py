from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import os

# Load environment variables from a .env file at repo root (without extra dependencies)
def _load_env_file():
    try:
        root = os.getcwd()
        env_path = os.path.join(root, '.env')
        if not os.path.exists(env_path):
            return
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    s = line.strip()
                    if not s or s.startswith('#'):
                        continue
                    if '=' not in s:
                        continue
                    key, val = s.split('=', 1)
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and (key not in os.environ):
                        os.environ[key] = val
                except Exception:
                    continue
    except Exception:
        pass

_load_env_file()

# Rate limiting (slowapi)
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi.staticfiles import StaticFiles

# Centralized logging setup
try:
    # When running as a package
    from .utils.logger import setup_logging, RequestContextLogMiddleware  # type: ignore
except Exception:
    # When running flat from repo root
    from utils.logger import setup_logging, RequestContextLogMiddleware  # type: ignore

setup_logging()

# Routers: support both package-relative and flat repo imports
try:
    # Initialize PostgreSQL connection
    try:
        # When running as a package
        from .db.database import get_connection  # type: ignore
    except Exception:
        # When running flat from repo root
        from db.database import get_connection  # type: ignore
    
    # Test database connection
    conn = get_connection()
    conn.close()
    logging.info("PostgreSQL database connection successful")
except Exception as e:
    logging.error(f"Failed to connect to PostgreSQL database: {e}")
    
# Import routers directly from the flat directory structure
# This is the most reliable approach for the production environment
from routers.core import router as core_router  # type: ignore
from routers.builder import router as builder_router  # type: ignore
from routers.payments import router as payments_router  # type: ignore
from routers.mailchimp import router as mailchimp_router  # type: ignore
from routers.google_sheets import router as google_sheets_router  # type: ignore
from routers.slack import router as slack_router  # type: ignore
from routers.admin import router as admin_router  # type: ignore
from routers.health import router as health_router  # type: ignore
from routers.translate import router as translate_router  # type: ignore
from routers.airtable import router as airtable_router  # type: ignore
from routers.url_validation import router as url_validation_router  # type: ignore
from routers.uploads import router as uploads_router  # type: ignore
from routers.forms_validated import router as forms_validated_router  # type: ignore
from routers.notifications import router as notifications_router  # type: ignore
from routers.analytics import router as analytics_router  # type: ignore
from routers.file_proxy import router as file_proxy_router  # type: ignore
from routers.form_versions import router as form_versions_router  # type: ignore
from routers.virus_scan import router as virus_scan_router  # type: ignore
from routers.live_visitors import router as live_visitors_router  # type: ignore
from routers.file_redirects import router as file_redirects_router  # type: ignore
from routers.custom_domain import router as custom_domain_router  # type: ignore
from routers.client_notifications import router as client_notifications_router  # type: ignore
from routers.geo_restrictions import router as geo_restrictions_router  # type: ignore
from routers.fonts import router as fonts_router  # type: ignore
from routers.user_stats import router as user_stats_router  # type: ignore
from routers.geocoding import router as geocoding_router  # type: ignore
from routers.schedules import router as schedules_router  # type: ignore
from routers.admin_live_visitors import router as admin_live_visitors_router  # type: ignore
from routers.user_analytics import router as user_analytics_router  # type: ignore
from routers.billing import router as billing_router  # type: ignore
from routers.api_keys import router as api_keys_router  # type: ignore
from routers.public_api import router as public_api_router  # type: ignore
from routers.affiliates_auth import router as affiliates_auth_router  # type: ignore
from routers.affiliates_stats import router as affiliates_stats_router  # type: ignore
from routers.affiliates_webhook import router as affiliates_webhook_router  # type: ignore
from routers.feature_requests import router as feature_requests_router  # type: ignore
from routers.developer_waitlist import router as developer_waitlist_router  # type: ignore

app = FastAPI(title="CleanEnroll API")

# Custom domain routing middleware: redirect host matches to SPA /form/{id}
from fastapi import Request
from fastapi.responses import RedirectResponse
import json as _json
import os as _os

DATA_FORMS_DIR = _os.path.join(_os.getcwd(), "data", "forms")
_os.makedirs(DATA_FORMS_DIR, exist_ok=True)
# ACME HTTP-01 challenge directory and static mount
ACME_CHALLENGE_DIR = _os.path.join(_os.getcwd(), "data", "acme", ".well-known", "acme-challenge")
_os.makedirs(ACME_CHALLENGE_DIR, exist_ok=True)
app.mount("/.well-known/acme-challenge", StaticFiles(directory=ACME_CHALLENGE_DIR), name="acme-challenge")

@app.middleware("http")
async def custom_domain_routing(request: Request, call_next):
    try:
        host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
        host = (host.split(":")[0] or "").strip().lower().strip(".")
        # Allow ACME HTTP-01 challenges to pass through without redirect
        try:
            path = request.url.path or ""
        except Exception:
            path = ""
        if path.startswith("/.well-known/acme-challenge/"):
            return await call_next(request)
        # Skip redirect if already on /form/* to avoid redundant redirects/loops
        if path.startswith("/form/"):
            return await call_next(request)
        if host:
            for name in _os.listdir(DATA_FORMS_DIR):
                if not name.endswith(".json"):
                    continue
                try:
                    with open(_os.path.join(DATA_FORMS_DIR, name), "r", encoding="utf-8") as f:
                        data = _json.load(f)
                    if data.get("customDomainVerified") and (str(data.get("customDomain") or "").strip().lower().strip(".") == host):
                        form_id = data.get("id") or name.replace(".json", "")
                        # Redirect to frontend SPA /form/{id}; the core router has a helper to forward to FRONTEND_URL if configured
                        return RedirectResponse(url=f"/form/{form_id}", status_code=307)
                except Exception:
                    continue
    except Exception:
        # On any error, continue normal handling
        pass
    return await call_next(request)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add Content-Security-Policy header to allow video embeds from YouTube, Vimeo, and Loom."""
    response = await call_next(request)
    # Allow iframe embeds from trusted video platforms
    response.headers["Content-Security-Policy"] = "frame-src 'self' https://www.youtube.com https://youtube.com https://*.youtube.com https://player.vimeo.com https://www.loom.com;"
    return response

# Production-safe error responses
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

def _is_production() -> bool:
    return (os.getenv("ENV") or os.getenv("APP_ENV") or os.getenv("NODE_ENV") or "").lower() == "production"

def _safe_message(status_code: int) -> str:
    mapping = {
        400: "Invalid request.",
        401: "Unauthorized.",
        403: "Action not allowed.",
        404: "Not found.",
        405: "Method not allowed.",
        409: "Conflict.",
        413: "Request too large.",
        415: "Unsupported request.",
        422: "Invalid request.",
        429: "Too many requests.",
        500: "Something went wrong. Please try again.",
        502: "Temporary service issue. Please try again.",
        503: "Service unavailable. Please try again.",
        504: "Timeout. Please try again.",
    }
    return mapping.get(int(status_code or 500), "Something went wrong. Please try again.")

@app.exception_handler(HTTPException)
async def http_exception_sanitizer(request: Request, exc: HTTPException):
    if _is_production():
        # Preserve status code; sanitize message
        return JSONResponse(status_code=exc.status_code, content={"detail": _safe_message(exc.status_code)})
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc.detail) if getattr(exc, "detail", None) else _safe_message(exc.status_code)})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Always sanitize validation errors
    status = 422
    return JSONResponse(status_code=status, content={"detail": _safe_message(status)})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logging.getLogger("backend").exception("Unhandled error")
    return JSONResponse(status_code=500, content={"detail": _safe_message(500)})

# Import shared forwarded_for_ip and limiter
try:
    from .utils.limiter import forwarded_for_ip, limiter  # type: ignore
except Exception:
    from utils.limiter import forwarded_for_ip, limiter  # type: ignore
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded"}
    )

app.add_middleware(SlowAPIMiddleware)

# CORS (embedding and local development)
# CORS allowed origins: env override (CORS_ALLOWED_ORIGINS comma-separated), else defaults
_env_origins_list = []
try:
    _raw = os.getenv("CORS_ALLOWED_ORIGINS") or ""
    if _raw:
        _env_origins_list = [o.strip() for o in _raw.split(",") if o.strip()]
except Exception:
    _env_origins_list = []
_default_origins = [
    "https://cleanenroll.com",
    "https://www.cleanenroll.com",
    "https://api.cleanenroll.com",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
# Optionally include FRONTEND_URL values
_extra = []
for k in ("FRONTEND_URL", "FRONTEND_URL2", "CORS_ORIGIN", "CORS_ORIGINS"):
    try:
        v = (os.getenv(k) or "").strip()
        if v:
            # support comma-separated in CORS_ORIGINS
            if "," in v:
                _extra.extend([x.strip() for x in v.split(",") if x.strip()])
            else:
                _extra.append(v)
    except Exception:
        continue
_allow_origins = _env_origins_list or list(dict.fromkeys(_default_origins + _extra))

# Allow all origins for custom domain support
# Custom domains (e.g., form.quickcap.pro) need to fetch forms from API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for custom domains
    allow_credentials=False,  # Must be False when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/response logging middleware
app.add_middleware(RequestContextLogMiddleware)

# Include routers
app.include_router(core_router)
app.include_router(builder_router)
app.include_router(payments_router)
app.include_router(mailchimp_router)
app.include_router(google_sheets_router)
app.include_router(slack_router)
app.include_router(admin_router)
app.include_router(health_router)
app.include_router(translate_router)
app.include_router(airtable_router)
app.include_router(url_validation_router)
app.include_router(uploads_router)
app.include_router(forms_validated_router, prefix="/api/v1")
app.include_router(notifications_router)
app.include_router(analytics_router)
app.include_router(file_proxy_router)
app.include_router(form_versions_router)
app.include_router(virus_scan_router)
app.include_router(live_visitors_router)
app.include_router(file_redirects_router)
app.include_router(custom_domain_router, prefix="/api")
app.include_router(client_notifications_router, prefix="/api")
app.include_router(geo_restrictions_router, prefix="/api")
app.include_router(fonts_router)
app.include_router(user_stats_router)
app.include_router(geocoding_router)
app.include_router(schedules_router)
app.include_router(admin_live_visitors_router)
app.include_router(user_analytics_router)
app.include_router(billing_router)
app.include_router(api_keys_router)  # Developer API key management
app.include_router(public_api_router)  # Public API for developers
app.include_router(affiliates_auth_router, prefix="/api/affiliates/auth")  # Affiliate authentication
app.include_router(affiliates_stats_router, prefix="/api/affiliates")  # Affiliate stats and analytics
app.include_router(affiliates_webhook_router, prefix="/api/affiliates")  # Affiliate webhook handlers
app.include_router(feature_requests_router, prefix="/api")  # Feature requests
app.include_router(developer_waitlist_router)  # Developer portal waitlist


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
