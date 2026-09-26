"""
Async SQLAlchemy engine and session management.

SQLite is used for local development; PostgreSQL (asyncpg) for production.
The engine is created lazily so that importing the app never opens a
connection -- important for the test suite.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Declarative base for every SentinelForge ORM model."""


def _build_engine() -> AsyncEngine:
    kwargs: dict = {"echo": settings.db_echo, "future": True}

    if settings.is_sqlite:
        # SQLite has no server-side pooling to configure, but we must let
        # async drivers share a connection across the session.
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_pre_ping"] = True
        kwargs["pool_size"] = 10
        kwargs["max_overflow"] = 20

    return create_async_engine(settings.database_url, **kwargs)


engine: AsyncEngine = _build_engine()

if settings.is_sqlite:

    @event.listens_for(engine.sync_engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _connection_record):
        """Enable FK enforcement and WAL for concurrent scan writes."""
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.close()


async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a transactional session.

    Commits on success, rolls back on any exception. Importing the model
    registry here guarantees ``create_all`` sees every table.
    """
    from app import models  # noqa: F401  (registers mappers)

    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def session_scope() -> AsyncGenerator[AsyncSession, None]:
    """Standalone transactional scope for background workers (orchestrator)."""
    from app import models  # noqa: F401

    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables. Idempotent."""
    from app import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema ready (%s)", "sqlite" if settings.is_sqlite else "postgres")


async def close_db() -> None:
    await engine.dispose()
