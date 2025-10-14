"""
PostgreSQL database connection module for CleanEnroll using SQLAlchemy async engine with connection pooling
"""

import os
import asyncio
from typing import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import text
from sqlalchemy.engine import URL
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables (do not override shell env)
try:
    load_dotenv()
    backend_env = Path(__file__).resolve().parents[1] / ".env"
    if backend_env.exists():
        load_dotenv(dotenv_path=str(backend_env), override=False)
except Exception:
    pass

# Database connection parameters (Neon-first)
DATABASE_URL_ENV = os.getenv("DATABASE_URL", "")
DB_NAME = os.getenv("NEON_DB", os.getenv("POSTGRES_DB", "neondb"))
DB_USER = os.getenv("NEON_USER", os.getenv("POSTGRES_USER", "neondb_owner"))
DB_PASSWORD = os.getenv("NEON_PASSWORD", os.getenv("POSTGRES_PASSWORD", ""))
DB_HOST = os.getenv("NEON_HOST", os.getenv("POSTGRES_HOST", "localhost"))
DB_PORT = os.getenv("NEON_PORT", os.getenv("POSTGRES_PORT", "5432"))
DB_SSLMODE = os.getenv("DB_SSLMODE", "require")

# SQLAlchemy models base class
Base = declarative_base()

# Create async engine with connection pooling
def _normalize_asyncpg_url(dsn: str) -> str:
    # Ensure SQLAlchemy uses asyncpg driver
    if dsn.startswith("postgresql+asyncpg://"):
        return dsn
    if dsn.startswith("postgresql://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql://"):]
    return dsn

if DATABASE_URL_ENV:
    raw_url = _normalize_asyncpg_url(DATABASE_URL_ENV)
    DATABASE_URL = raw_url
else:
    # Build from discrete env vars
    DATABASE_URL = str(
        URL.create(
            drivername="postgresql+asyncpg",
            username=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=int(DB_PORT) if str(DB_PORT).isdigit() else None,
            database=DB_NAME,
            query={"sslmode": DB_SSLMODE},
        )
    )

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,
    pool_pre_ping=True,
)

# Create session factory
async_session_maker = async_sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)

# For backward compatibility with existing code
async def get_connection():
    """Get a SQLAlchemy async session"""
    return async_session_maker()

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an AsyncSession and manages commit/rollback/close."""
    session = async_session_maker()
    try:
        yield session
        await session.commit()
    except Exception as e:
        await session.rollback()
        raise e
    finally:
        await session.close()

# For backward compatibility with existing code that uses get_cursor
@asynccontextmanager
async def get_cursor(commit=False):
    """Async context manager that provides raw SQL execution capability"""
    async with async_session_maker() as session:
        try:
            async with session.begin():
                # This allows executing raw SQL while still using the connection pool
                await session.execute(text("SELECT 1"))
                # Create a proxy object that mimics the old cursor interface
                cursor_proxy = SQLAlchemyCursorProxy(session)
                yield cursor_proxy
            if commit:
                await session.commit()
        except Exception as e:
            await session.rollback()
            raise e

class SQLAlchemyCursorProxy:
    """A proxy class that mimics the psycopg2 cursor interface but uses SQLAlchemy under the hood"""
    
    def __init__(self, session):
        self.session = session
        self._results = None
        
    async def execute(self, query, params=None):
        """Execute a SQL query"""
        if params:
            result = await self.session.execute(text(query), params)
        else:
            result = await self.session.execute(text(query))
        self._results = result
        return result
    
    async def fetchall(self):
        """Fetch all results as dictionaries"""
        if not self._results:
            return []
        result = self._results.mappings().all()
        return [dict(row) for row in result]
    
    async def fetchone(self):
        """Fetch one result as a dictionary"""
        if not self._results:
            return None
        row = self._results.mappings().first()
        return dict(row) if row else None