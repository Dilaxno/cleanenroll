from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import os

# Rate limiting (slowapi)
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

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
    # When running as a package: e.g. `uvicorn backend.main:app` or `python -m backend.main`
    from .routers.core import router as core_router  # type: ignore
    from .routers.builder import router as builder_router  # type: ignore
    from .routers.payments import router as payments_router  # type: ignore
    from .routers.mailchimp import router as mailchimp_router  # type: ignore
except Exception:
    # When running from a flat repo root: e.g. `uvicorn main:app`
    from routers.core import router as core_router  # type: ignore
    from routers.builder import router as builder_router  # type: ignore
    from routers.payments import router as payments_router  # type: ignore
    from routers.mailchimp import router as mailchimp_router  # type: ignore

app = FastAPI(title="CleanEnroll API")

# Custom domain routing middleware: redirect host matches to SPA /form/{id}
from fastapi import Request
from fastapi.responses import RedirectResponse
import json as _json
import os as _os

DATA_FORMS_DIR = _os.path.join(_os.getcwd(), "data", "forms")
_os.makedirs(DATA_FORMS_DIR, exist_ok=True)

@app.middleware("http")
async def custom_domain_routing(request: Request, call_next):
    try:
        host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
        host = (host.split(":")[0] or "").strip().lower().strip(".")
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
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS (embedding and local development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
