from fastapi import Request
from slowapi import Limiter


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
