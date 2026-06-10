"""Runtime configuration, sourced from the environment only (no secrets in code).

``DATABASE_URL`` must be an async SQLAlchemy URL (``postgresql+asyncpg://...`` in production,
``sqlite+aiosqlite://...`` in tests). All settings are read once and cached.
"""

from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Platform settings read from environment variables / a local ``.env`` file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Async SQLAlchemy URL. Default targets the docker-compose Postgres for local dev.
    database_url: str = "postgresql+asyncpg://vulnadvisor:vulnadvisor@localhost:5432/vulnadvisor"

    # Echo SQL (dev debugging only).
    db_echo: bool = False

    # Secret used to sign session cookies. MUST be overridden in production (env SECRET_KEY).
    secret_key: str = "dev-insecure-secret-change-in-production"

    # GitHub OAuth app credentials (dashboard login). Empty in dev/tests.
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = "http://localhost:8000/v1/auth/github/callback"

    # Where to send the browser after a successful login.
    dashboard_url: str = "http://localhost:3000"

    # GitHub App (webhooks + PR comments). Empty in dev/tests.
    github_webhook_secret: str = ""
    github_app_slug: str = ""
    github_app_id: str = ""
    github_app_private_key: str = ""


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()


# FastAPI dependency for settings (overridable in tests, e.g. to inject a webhook secret).
SettingsDep = Annotated[Settings, Depends(get_settings)]
