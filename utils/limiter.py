from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from datetime import datetime, timedelta
import os
import json
from typing import Optional

# Redis support for distributed rate limiting
try:
    import redis
    _REDIS_AVAILABLE = True
except ImportError:
    redis = None  # type: ignore
    _REDIS_AVAILABLE = False

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


def _get_redis_storage():
    """Get Redis storage for rate limiting if configured."""
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url or not _REDIS_AVAILABLE:
        return None
    
    try:
        from slowapi.util import get_remote_address
        # Import the Redis storage backend for slowapi
        try:
            from limits.storage import RedisStorage
            return RedisStorage(redis_url)
        except ImportError:
            # Fallback: try older limits package API
            try:
                from limits.strategies import MovingWindowRateLimiter
                from limits.storage import storage_from_string
                return storage_from_string(redis_url)
            except Exception:
                pass
    except Exception as e:
        print(f"[limiter] Failed to initialize Redis storage: {e}")
    
    return None


def _create_limiter():
    """Create limiter with Redis storage if available, otherwise use in-memory."""
    storage = _get_redis_storage()
    
    if storage:
        print("[limiter] Using Redis for rate limiting")
        return Limiter(
            key_func=get_remote_address,
            storage_uri=os.environ.get("REDIS_URL"),
        )
    else:
        print("[limiter] Using in-memory rate limiting (Redis not configured)")
        return Limiter(key_func=get_remote_address)


# Global limiter instance to be shared across the app and routers
limiter = _create_limiter()


# Redis client for signup attempts (separate from slowapi)
_redis_client = None

def _get_redis_client():
    """Get or create Redis client for signup tracking."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url or not _REDIS_AVAILABLE:
        return None
    
    try:
        _redis_client = redis.from_url(redis_url, decode_responses=True)
        # Test connection
        _redis_client.ping()
        print("[limiter] Redis client connected for signup tracking")
        return _redis_client
    except Exception as e:
        print(f"[limiter] Failed to connect to Redis: {e}")
        _redis_client = None
        return None


# Persistent store for signup attempts by IP (24h gap) - file-based fallback
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
    """Return (allowed, retry_after_seconds). Uses Redis if available, else file store.
    If allowed, caller should record the attempt via record_signup_ip.
    """
    if not ip:
        # If we can't resolve IP, allow but do not record; upstream may block separately
        return True, None
    
    # Try Redis first
    redis_client = _get_redis_client()
    if redis_client:
        try:
            key = f"signup_attempt:{ip}"
            last = redis_client.get(key)
            if last:
                last_dt = datetime.fromisoformat(last)
                delta = datetime.utcnow() - last_dt
                if delta < timedelta(hours=max(1, int(window_hours))):
                    retry = int((timedelta(hours=window_hours) - delta).total_seconds())
                    return False, max(1, retry)
            return True, None
        except Exception as e:
            print(f"[limiter] Redis error in can_signup_ip: {e}")
            # Fall through to file-based storage
    
    # Fallback to file-based storage
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


def record_signup_ip(ip: str, window_hours: int = 24) -> None:
    """Record a signup attempt for the given IP."""
    if not ip:
        return
    
    # Try Redis first
    redis_client = _get_redis_client()
    if redis_client:
        try:
            key = f"signup_attempt:{ip}"
            redis_client.setex(
                key,
                timedelta(hours=window_hours),
                datetime.utcnow().isoformat()
            )
            return
        except Exception as e:
            print(f"[limiter] Redis error in record_signup_ip: {e}")
            # Fall through to file-based storage
    
    # Fallback to file-based storage
    data = _load_signup_store()
    data[ip] = datetime.utcnow().isoformat()
    _save_signup_store(data)
