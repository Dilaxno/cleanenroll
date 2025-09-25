from fastapi import Request
from slowapi import Limiter
from datetime import datetime, timedelta
import os
import json
from typing import Optional
try:
    from fastratelimiter import FastRateLimiter  # type: ignore
    _FRL_AVAILABLE = True
except Exception:
    FastRateLimiter = None  # type: ignore
    _FRL_AVAILABLE = False


def forwarded_for_ip(request: Request) -> str:
    """Resolve client IP using X-Forwarded-For first, then fallback to socket IP."""
    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if xff:
        ip = xff.split(',')[0].strip()
        if ip:
            return ip
    return request.client.host if request.client else ""


# Global limiter instance to be shared across the app and routers
limiter = Limiter(key_func=forwarded_for_ip)

# Persistent store for signup attempts by IP (24h gap)
_SIGNUP_STORE_PATH = os.path.join(os.getcwd(), 'data', 'signup_attempts.json')
os.makedirs(os.path.dirname(_SIGNUP_STORE_PATH), exist_ok=True)

def _load_signup_store() -> dict:
    try:
        with open(_SIGNUP_STORE_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _save_signup_store(data: dict) -> None:
    try:
        with open(_SIGNUP_STORE_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception:
        pass

def can_signup_ip(ip: str, window_hours: int = 24) -> tuple[bool, Optional[int]]:
    """Return (allowed, retry_after_seconds). Uses persistent file store.
    If allowed, caller should record the attempt via record_signup_ip.
    """
    if not ip:
        # If we can't resolve IP, allow but do not record; upstream may block separately
        return True, None
    data = _load_signup_store()
    last = str(data.get(ip) or '')
    try:
        if last:
            last_dt = datetime.fromisoformat(last)
            delta = datetime.utcnow() - last_dt
            if delta < timedelta(hours=max(1, int(window_hours))):
                retry = int((timedelta(hours=window_hours) - delta).total_seconds())
                return False, max(1, retry)
    except Exception:
        pass
    return True, None

def record_signup_ip(ip: str) -> None:
    if not ip:
        return
    data = _load_signup_store()
    data[ip] = datetime.utcnow().isoformat()
    _save_signup_store(data)
