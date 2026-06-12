"""Copilot settings + grant endpoints (Task 15.1).

Two surfaces with very different trust levels:

* **Settings** (``GET /settings/copilot``, ``PUT``/``DELETE /settings/copilot-key``) — normal
  org-scoped dashboard endpoints. The key is accepted once, stored encrypted (Fernet under a
  ``SECRET_KEY`` derivation), and *never returned*: responses carry only ``byo_key_set`` and a
  ``…last4`` hint.
* **Grant** (``POST /copilot/grant``) — service-to-service only. The dashboard's ``/api/copilot``
  route handler presents the shared ``COPILOT_SERVICE_TOKEN`` *and* forwards the caller's own
  session; the response is the decrypted BYO key (or the platform-fallback marker) plus one slot
  under the org's daily cap. Users never hold the service token, so no user-reachable endpoint
  can produce the key. Tenant isolation is the caller's own membership (``require_org`` → 404),
  not a service account.
"""

import hmac
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Response, status

from vulnadvisor_platform.access import require_admin, require_org
from vulnadvisor_platform.config import SettingsDep
from vulnadvisor_platform.copilot import (
    CopilotCapExceeded,
    CopilotKeyError,
    consume_grant,
    decrypt_api_key,
    encrypt_api_key,
    key_hint,
    used_today,
    validate_anthropic_key,
)
from vulnadvisor_platform.db import SessionDep
from vulnadvisor_platform.schemas import CopilotGrant, CopilotKeySet, CopilotSettingsOut
from vulnadvisor_platform.security import CurrentUser

router = APIRouter(tags=["copilot"])

_ServiceToken = Annotated[str | None, Header(alias="X-Copilot-Service")]


@router.get("/v1/orgs/{org_slug}/settings/copilot", response_model=CopilotSettingsOut)
async def get_copilot_settings(
    org_slug: str, user: CurrentUser, session: SessionDep, settings: SettingsDep
) -> CopilotSettingsOut:
    """Copilot settings for the org: key hint (never the key), cap, and today's usage."""
    org, _ = await require_org(session, user, org_slug)
    return CopilotSettingsOut(
        byo_key_set=org.copilot_key_ciphertext is not None,
        key_hint=org.copilot_key_hint,
        daily_cap=settings.copilot_daily_cap,
        used_today=await used_today(session, org.id),
    )


@router.put("/v1/orgs/{org_slug}/settings/copilot-key", response_model=CopilotSettingsOut)
async def set_copilot_key(
    org_slug: str,
    body: CopilotKeySet,
    user: CurrentUser,
    session: SessionDep,
    settings: SettingsDep,
) -> CopilotSettingsOut:
    """Store the org's BYO Anthropic key encrypted at rest (owner/admin only)."""
    org, role = await require_org(session, user, org_slug)
    require_admin(role)
    try:
        api_key = validate_anthropic_key(body.api_key)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    org.copilot_key_ciphertext = encrypt_api_key(settings.secret_key, api_key)
    org.copilot_key_hint = key_hint(api_key)
    await session.commit()
    return CopilotSettingsOut(
        byo_key_set=True,
        key_hint=org.copilot_key_hint,
        daily_cap=settings.copilot_daily_cap,
        used_today=await used_today(session, org.id),
    )


@router.delete("/v1/orgs/{org_slug}/settings/copilot-key", status_code=status.HTTP_204_NO_CONTENT)
async def clear_copilot_key(org_slug: str, user: CurrentUser, session: SessionDep) -> Response:
    """Remove the org's BYO key (owner/admin only). Idempotent."""
    org, role = await require_org(session, user, org_slug)
    require_admin(role)
    if org.copilot_key_ciphertext is not None or org.copilot_key_hint is not None:
        org.copilot_key_ciphertext = None
        org.copilot_key_hint = None
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/v1/orgs/{org_slug}/copilot/grant", response_model=CopilotGrant)
async def copilot_grant(
    org_slug: str,
    user: CurrentUser,
    session: SessionDep,
    settings: SettingsDep,
    x_copilot_service: _ServiceToken = None,
) -> CopilotGrant:
    """Exchange the service token + the caller's own session for one copilot request grant.

    This is the **only** place the decrypted BYO key ever leaves the platform, and it requires
    the shared service token users never see. The caller's membership scopes the org (404 for
    non-members), and the org's daily cap is consumed atomically with the grant (429 when spent).
    """
    if not settings.copilot_service_token:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "copilot grant disabled (COPILOT_SERVICE_TOKEN not configured)",
        )
    if x_copilot_service is None or not hmac.compare_digest(
        x_copilot_service, settings.copilot_service_token
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "copilot grant requires the service token")

    org, _ = await require_org(session, user, org_slug)

    try:
        remaining = await consume_grant(session, org.id, settings.copilot_daily_cap)
    except CopilotCapExceeded as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc

    api_key: str | None = None
    if org.copilot_key_ciphertext is not None:
        try:
            api_key = decrypt_api_key(settings.secret_key, org.copilot_key_ciphertext)
        except CopilotKeyError as exc:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from exc

    await session.commit()  # the grant is consumed only when the response succeeds
    return CopilotGrant(
        key_source="org" if api_key is not None else "platform",
        api_key=api_key,
        remaining_today=remaining,
    )
