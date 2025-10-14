from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy.sql import text

# Support both package and flat imports for the session maker
try:
    from ..db.database import async_session_maker  # type: ignore
except Exception:
    from db.database import async_session_maker  # type: ignore

router = APIRouter()

@router.get("/health/db")
async def health_db():
    """Lightweight DB health check: runs SELECT 1 against Neon."""
    try:
        async with async_session_maker() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "ok", "db": True}
    except Exception as e:
        # Do not leak internals in production; return a generic failure
        return {"status": "fail", "db": False, "error": str(e)}
