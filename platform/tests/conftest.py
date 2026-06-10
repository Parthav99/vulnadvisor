"""Test fixtures for the platform: a hermetic in-memory async DB and an ASGI client.

No Postgres or Docker needed here — models run on in-memory SQLite (shared across sessions via
``StaticPool``) so the suite is fast and offline. The live Postgres migration is validated
separately via ``alembic upgrade head`` against docker-compose.
"""

from collections.abc import AsyncIterator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from vulnadvisor_platform.app import app
from vulnadvisor_platform.db import Base, get_session
from vulnadvisor_platform.models import ApiKey, Membership, Org, Role, User
from vulnadvisor_platform.security import generate_api_key


@pytest_asyncio.fixture
async def sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """A session factory over a fresh, shared in-memory SQLite database with the schema created."""
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def seeded_key(sessionmaker: async_sessionmaker[AsyncSession]) -> str:
    """Seed one user + org (owner membership) + API key; return the plaintext key."""
    full, prefix, digest = generate_api_key()
    async with sessionmaker() as session:
        user = User(login="octocat", email="octocat@example.com", github_user_id=1)
        org = Org(slug="acme", name="Acme Inc", github_org_id=10)
        session.add_all([user, org])
        await session.flush()
        session.add(Membership(user_id=user.id, org_id=org.id, role=Role.OWNER.value))
        session.add(
            ApiKey(org_id=org.id, name="ci-key", hash=digest, prefix=prefix, created_by=user.id)
        )
        await session.commit()
    return full


@pytest_asyncio.fixture
async def client(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    """An ASGI client whose ``get_session`` dependency is bound to the in-memory database."""

    async def _override_session() -> AsyncIterator[AsyncSession]:
        async with sessionmaker() as session:
            yield session

    app.dependency_overrides[get_session] = _override_session
    transport = ASGITransport(app=app)
    # https base URL so the now-Secure session cookie round-trips through httpx's cookie jar
    # (Secure cookies are only sent over https), matching production behaviour.
    async with AsyncClient(transport=transport, base_url="https://test") as http_client:
        yield http_client
    app.dependency_overrides.clear()
