import logging
import os
import sys
import time
import uuid
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv(
    "LOG_FORMAT",
    "%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


def setup_logging() -> None:
    """Configure root logging and common third-party loggers (uvicorn).

    - Level controlled by LOG_LEVEL env var (default INFO)
    - Simple, readable console formatter by default
    - Align uvicorn loggers with our level
    """
    # If logging is already configured (e.g., by uvicorn), don't add duplicate handlers
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root.addHandler(handler)
    root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # Align uvicorn loggers
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        try:
            logging.getLogger(name).setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
        except Exception:
            pass


class RequestContextLogMiddleware(BaseHTTPMiddleware):
    """Middleware that:
    - Generates a request_id (or uses incoming X-Request-ID)
    - Logs request start and completion with latency and status code
    - Attaches request_id to response headers
    """

    def __init__(self, app, get_request_body: bool = False):
        super().__init__(app)
        self.get_request_body = get_request_body
        self.logger = logging.getLogger("backend.http")

    async def dispatch(self, request: Request, call_next: Callable):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        start = time.time()

        path = request.url.path
        method = request.method
        client = request.client.host if request.client else ""

        # Optionally capture a small request body for debugging (avoid large/PII)
        body_snippet = None
        if self.get_request_body:
            try:
                body_bytes = await request.body()
                if body_bytes:
                    body_snippet = body_bytes[:512].decode("utf-8", errors="replace")
            except Exception:
                body_snippet = None

        self.logger.info(
            "request start %s %s client=%s rid=%s",
            method,
            path,
            client,
            request_id,
        )

        try:
            response = await call_next(request)
            status = response.status_code
            elapsed_ms = int((time.time() - start) * 1000)
            response.headers["x-request-id"] = request_id
            self.logger.info(
                "request end %s %s status=%s time_ms=%s rid=%s",
                method,
                path,
                status,
                elapsed_ms,
                request_id,
            )
            return response
        except Exception:
            elapsed_ms = int((time.time() - start) * 1000)
            self.logger.exception(
                "request error %s %s time_ms=%s rid=%s",
                method,
                path,
                elapsed_ms,
                request_id,
            )
            raise
