"""API-key hashing and the Bearer authentication dependency.

Minimal credential layer for Task 11.2: a client presents ``Authorization: Bearer <api_key>``; we
SHA-256 it and look up a non-revoked :class:`ApiKey`, resolving the user who created it. Full GitHub
OAuth / session login is Task 11.5; this is the production-shaped API-key half it will build on.

Only the hash is ever stored. The plaintext key has the form ``<prefix>.<body>`` so the non-secret
``prefix`` can be shown in listings while the body stays secret.
"""

import hashlib
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from vulnadvisor_platform.db import SessionDep, utcnow
from vulnadvisor_platform.models import ApiKey, User

_PREFIX_TAG = "va"
_bearer = HTTPBearer(auto_error=False)
_CredentialsDep = Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]


def hash_key(secret: str) -> str:
    """Return the hex SHA-256 of an API key (the only form ever stored)."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Mint a new API key.

    Returns ``(full_secret, prefix, hash)``: show ``full_secret`` to the user exactly once, store
    ``prefix`` (for identification) and ``hash`` (for verification).
    """
    prefix = f"{_PREFIX_TAG}_{secrets.token_hex(4)}"
    body = secrets.token_urlsafe(32)
    full = f"{prefix}.{body}"
    return full, prefix, hash_key(full)


async def get_current_user(credentials: _CredentialsDep, session: SessionDep) -> User:
    """Resolve the authenticated user from a Bearer API key, or raise 401.

    Rejects a missing/non-Bearer header, an unknown or revoked key, and a key whose creating user no
    longer exists. On success, stamps ``last_used_at`` and returns the :class:`User`.
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing or invalid API key",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized

    digest = hash_key(credentials.credentials)
    key = (
        await session.execute(
            select(ApiKey).where(ApiKey.hash == digest, ApiKey.revoked_at.is_(None))
        )
    ).scalar_one_or_none()
    if key is None or key.created_by is None:
        raise unauthorized

    user = await session.get(User, key.created_by)
    if user is None:
        raise unauthorized

    key.last_used_at = utcnow()
    await session.commit()
    return user


# Reusable FastAPI dependency annotation for the authenticated user.
CurrentUser = Annotated[User, Depends(get_current_user)]
