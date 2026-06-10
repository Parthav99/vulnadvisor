"""Runtime configuration, sourced from the environment only (no secrets in code).

``DATABASE_URL`` must be an async SQLAlchemy URL (``postgresql+asyncpg://...`` in production,
``sqlite+aiosqlite://...`` in tests). All settings are read once and cached.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Platform settings read from environment variables / a local ``.env`` file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Async SQLAlchemy URL. Default targets the docker-compose Postgres for local dev.
    database_url: str = "postgresql+asyncpg://vulnadvisor:vulnadvisor@localhost:5432/vulnadvisor"

    # Echo SQL (dev debugging only).
    db_echo: bool = False


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
