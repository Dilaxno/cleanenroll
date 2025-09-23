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
except Exception:
    # When running from a flat repo root: e.g. `uvicorn main:app`
    from routers.core import router as core_router  # type: ignore
    from routers.builder import router as builder_router  # type: ignore
    from routers.payments import router as payments_router  # type: ignore

app = FastAPI(title="CleanEnroll API")

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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
