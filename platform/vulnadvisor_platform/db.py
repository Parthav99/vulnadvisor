"""Async SQLAlchemy engine, session factory, and declarative base.

The engine and session factory are created lazily from :func:`get_settings` so that importing the
models (e.g. for Alembic autogenerate) never requires a live database. Tests build their own engine
and override :func:`get_session`.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from vulnadvisor_platform.config import get_settings

# JSON on any backend; native JSONB on Postgres (for indexing/querying later).
JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    """Timezone-aware current time (UTC); used for created/updated defaults."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base for all platform models."""


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return the lazily-created async engine bound to ``DATABASE_URL``."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(settings.database_url, echo=settings.db_echo, future=True)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the lazily-created async session factory."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a request-scoped async session."""
    async with get_sessionmaker()() as session:
        yield session


# Reusable FastAPI dependency annotation for an async session.
SessionDep = Annotated[AsyncSession, Depends(get_session)]
