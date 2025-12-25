"""
PhotoMark proxy router

Proxies PhotoMark API requests using a server-side Bearer token to avoid exposing
secrets in the browser and to centralize error handling and caching.

Endpoint(s):
- GET /api/integrations/photomark/sales -> proxies to
  https://api.photomark.cloud/api/shop/sales with query params passthrough

Behavior:
- Reads PHOTOMARK_TOKEN from environment and sends Authorization: Bearer <token>
- Maps 401/403 from upstream to 502 for the frontend (with sanitized message)
- Honors 429 Retry-After header by relaying status and header to client
- Retries transient 5xx with exponential backoff
- Optional short-lived in-memory cache (~45s) to reduce upstream load
"""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
import os
import time
import httpx
from typing import Dict, Tuple, Optional

router = APIRouter(prefix="/api/integrations/photomark", tags=["photomark"])

PHOTOMARK_BASE = "https://api.photomark.cloud"
PHOTOMARK_TOKEN = os.getenv("PHOTOMARK_TOKEN", "").strip()

# Simple in-memory cache: key -> (expires_at_epoch_s, data)
_CACHE: Dict[str, Tuple[float, dict]] = {}
_CACHE_TTL_SECONDS = int(os.getenv("PHOTOMARK_CACHE_TTL", "45") or 45)

# HTTP client timeout
_TIMEOUT = httpx.Timeout(15.0)


def _cache_key(path: str, params: Dict[str, str]) -> str:
    # Stable key: path + sorted params
    items = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    return f"{path}?{items}" if items else path


async def _fetch_with_retries(url: str, headers: Dict[str, str], params: Dict[str, str]) -> httpx.Response:
    retries = 2  # total attempts = 1 + retries
    backoff = 0.5
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for attempt in range(retries + 1):
            try:
                resp = await client.get(url, headers=headers, params=params)
                # If 5xx and we still have attempts, retry
                if 500 <= resp.status_code < 600 and attempt < retries:
                    await _sleep(backoff)
                    backoff *= 2
                    continue
                return resp
            except httpx.TimeoutException:
                if attempt < retries:
                    await _sleep(backoff)
                    backoff *= 2
                    continue
                raise HTTPException(status_code=504, detail="Upstream timeout")
            except httpx.RequestError:
                if attempt < retries:
                    await _sleep(backoff)
                    backoff *= 2
                    continue
                raise HTTPException(status_code=503, detail="Upstream unavailable")


async def _sleep(seconds: float) -> None:
    # Small wrapper to avoid importing asyncio explicitly elsewhere
    import asyncio
    await asyncio.sleep(seconds)


@router.get("/sales")
async def get_sales(limit: int = Query(200, ge=1, le=1000), page: Optional[int] = Query(None, ge=1)):
    """Proxy PhotoMark sales with server-side auth.

    Query params are passed through. Caches successful JSON responses for ~45s.
    """
    if not PHOTOMARK_TOKEN:
        raise HTTPException(status_code=500, detail="Photomark token not configured")

    upstream_path = "/api/shop/sales"
    params: Dict[str, str] = {"limit": str(limit)}
    if page is not None:
        params["page"] = str(page)

    key = _cache_key(upstream_path, params)
    now = time.time()

    # Serve from cache if present and fresh
    cached = _CACHE.get(key)
    if cached and cached[0] > now:
        return cached[1]

    headers = {
        "Authorization": f"Bearer {PHOTOMARK_TOKEN}",
        "Accept": "application/json",
        "User-Agent": "CleanEnroll-Proxy/1.0",
    }

    url = f"{PHOTOMARK_BASE}{upstream_path}"
    resp = await _fetch_with_retries(url, headers=headers, params=params)

    # Map 401/403 to 502 with safe message
    if resp.status_code in (401, 403):
        # Do not leak upstream body; respond with 502 to the frontend
        raise HTTPException(status_code=502, detail="Photomark auth failed upstream")

    # Honor 429 by returning status and Retry-After if present
    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        headers_out = {"Retry-After": retry_after} if retry_after else {}
        # Return 429 with Retry-After header so clients can honor backoff guidance
        return JSONResponse(status_code=429, content={"detail": "Rate limited by Photomark"}, headers=headers_out)

    if 500 <= resp.status_code < 600:
        # After retries exhausted
        raise HTTPException(status_code=502, detail="Photomark service error")

    if resp.status_code != 200:
        # Propagate as a generic bad upstream
        raise HTTPException(status_code=502, detail=f"Unexpected Photomark response ({resp.status_code})")

    data = resp.json()

    # Cache successful responses
    _CACHE[key] = (now + _CACHE_TTL_SECONDS, data)

    return data
