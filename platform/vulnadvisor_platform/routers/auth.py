"""GitHub OAuth login for the dashboard (Task 11.5).

Flow: ``/login`` redirects to GitHub with a CSRF ``state`` (also set as a cookie); ``/callback``
verifies the state, exchanges the code, upserts the :class:`User`, and sets a signed session cookie;
``/logout`` clears it. The GitHub client is injected so tests run without network access.
"""

import secrets

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from vulnadvisor_platform.config import get_settings
from vulnadvisor_platform.db import SessionDep
from vulnadvisor_platform.github_oauth import OAuthDep
from vulnadvisor_platform.models import User
from vulnadvisor_platform.sessions import (
    OAUTH_STATE_COOKIE,
    clear_session_cookie,
    set_session_cookie,
)

router = APIRouter(prefix="/v1/auth", tags=["auth"])


@router.get("/github/login")
async def github_login(oauth: OAuthDep) -> RedirectResponse:
    """Begin the OAuth flow: redirect to GitHub with a fresh CSRF state."""
    state = secrets.token_urlsafe(24)
    response = RedirectResponse(
        oauth.authorize_url(state), status_code=status.HTTP_307_TEMPORARY_REDIRECT
    )
    response.set_cookie(OAUTH_STATE_COOKIE, state, max_age=600, httponly=True, samesite="lax")
    return response


@router.get("/github/callback")
async def github_callback(
    request: Request,
    code: str,
    state: str,
    oauth: OAuthDep,
    session: SessionDep,
) -> RedirectResponse:
    """Complete the OAuth flow: verify state, upsert the user, set the session cookie."""
    expected_state = request.cookies.get(OAUTH_STATE_COOKIE)
    if not expected_state or not secrets.compare_digest(expected_state, state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid OAuth state")

    token = await oauth.exchange_code(code)
    profile = await oauth.fetch_user(token)

    user = (
        await session.execute(select(User).where(User.github_user_id == profile.id))
    ).scalar_one_or_none()
    if user is None:
        user = User(
            github_user_id=profile.id,
            login=profile.login,
            email=profile.email,
            avatar_url=profile.avatar_url,
        )
        session.add(user)
    else:
        user.login = profile.login
        user.email = profile.email
        user.avatar_url = profile.avatar_url
    await session.commit()
    await session.refresh(user)

    response = RedirectResponse(
        get_settings().dashboard_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT
    )
    set_session_cookie(response, user.id)
    response.delete_cookie(OAUTH_STATE_COOKIE)
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout() -> Response:
    """Clear the session cookie."""
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(response)
    return response
