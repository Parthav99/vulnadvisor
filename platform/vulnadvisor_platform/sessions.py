"""Signed-cookie sessions for the dashboard (Task 11.5).

The session cookie holds ``"<user_id>.<hmac>"`` signed with ``SECRET_KEY``; there is no server-side
session store. ``hmac.compare_digest`` guards verification against timing attacks. This is the
dashboard's auth; CI/CLI continue to use org-scoped API keys.
"""

import hashlib
import hmac
import uuid

from fastapi import Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from vulnadvisor_platform.config import get_settings
from vulnadvisor_platform.models import User

SESSION_COOKIE = "va_session"
OAUTH_STATE_COOKIE = "va_oauth_state"
_SESSION_MAX_AGE = 60 * 60 * 24 * 14  # 14 days


def sign_session(user_id: str, secret: str) -> str:
    """Return ``"<user_id>.<hmac-sha256>"`` for the session cookie value."""
    signature = hmac.new(
        secret.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{user_id}.{signature}"


def verify_session(token: str, secret: str) -> str | None:
    """Return the user id if ``token``'s signature is valid, else ``None``."""
    try:
        user_id, signature = token.rsplit(".", 1)
    except ValueError:
        return None
    expected = hmac.new(secret.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
    return user_id if hmac.compare_digest(signature, expected) else None


async def user_from_session(request: Request, session: AsyncSession) -> User | None:
    """Resolve the logged-in user from the session cookie, or ``None``."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    user_id = verify_session(token, get_settings().secret_key)
    if user_id is None:
        return None
    try:
        parsed = uuid.UUID(user_id)
    except ValueError:
        return None
    return await session.get(User, parsed)


def set_session_cookie(response: Response, user_id: uuid.UUID) -> None:
    """Set the signed session cookie for ``user_id`` on ``response``."""
    token = sign_session(str(user_id), get_settings().secret_key)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=_SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
    )


def clear_session_cookie(response: Response) -> None:
    """Remove the session cookie (logout)."""
    response.delete_cookie(SESSION_COOKIE)
