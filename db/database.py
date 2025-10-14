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
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection parameters
DB_NAME = os.getenv("POSTGRES_DB", "cleanenroll")
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "Esstafa00uni@")
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")

# SQLAlchemy models base class
Base = declarative_base()

# Create async engine with connection pooling
DATABASE_URL = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    pool_size=5,  # Number of connections to keep open
    max_overflow=10,  # Max number of connections to create beyond pool_size
    pool_timeout=30,  # Seconds to wait before giving up on getting a connection
    pool_recycle=1800,  # Recycle connections after 30 minutes
    pool_pre_ping=True,  # Verify connections before using them
)

# Create session factory
async_session_maker = async_sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)

# For backward compatibility with existing code
async def get_connection():
    """Get a SQLAlchemy async session"""
    return async_session_maker()

@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager for database sessions"""
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
    async with get_session() as session:
        async with session.begin():
            # This allows executing raw SQL while still using the connection pool
            result_proxy = await session.execute(text("SELECT 1"))
            # Create a proxy object that mimics the old cursor interface
            cursor_proxy = SQLAlchemyCursorProxy(session)
            yield cursor_proxy
            if commit:
                await session.commit()

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