"""API-key management (Task 11.5): list / create / revoke org-scoped keys.

Dashboard endpoints (session or Bearer auth). The secret is returned **once** at creation and never
again; only its hash + prefix are stored. Creating and revoking require owner/admin; listing is open
to any org member.
"""

import uuid

from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import select

from vulnadvisor_platform.access import require_admin, require_org
from vulnadvisor_platform.db import SessionDep, utcnow
from vulnadvisor_platform.models import ApiKey
from vulnadvisor_platform.schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyOut
from vulnadvisor_platform.security import CurrentUser, generate_api_key

router = APIRouter(tags=["api-keys"])


@router.get("/v1/orgs/{org_slug}/keys", response_model=list[ApiKeyOut])
async def list_keys(org_slug: str, user: CurrentUser, session: SessionDep) -> list[ApiKeyOut]:
    """List an org's API keys (metadata only — never the secret or hash)."""
    org, _ = await require_org(session, user, org_slug)
    keys = (
        (
            await session.execute(
                select(ApiKey).where(ApiKey.org_id == org.id).order_by(ApiKey.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [ApiKeyOut.model_validate(key) for key in keys]


@router.post(
    "/v1/orgs/{org_slug}/keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
async def create_key(
    org_slug: str, body: ApiKeyCreate, user: CurrentUser, session: SessionDep
) -> ApiKeyCreated:
    """Create a key (owner/admin only); the secret is returned exactly once."""
    org, role = await require_org(session, user, org_slug)
    require_admin(role)
    secret, prefix, digest = generate_api_key()
    key = ApiKey(org_id=org.id, name=body.name, hash=digest, prefix=prefix, created_by=user.id)
    session.add(key)
    await session.commit()
    await session.refresh(key)
    return ApiKeyCreated(
        id=key.id, name=key.name, prefix=key.prefix, created_at=key.created_at, secret=secret
    )


@router.delete("/v1/orgs/{org_slug}/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(
    org_slug: str, key_id: uuid.UUID, user: CurrentUser, session: SessionDep
) -> Response:
    """Revoke a key (owner/admin only). Idempotent."""
    org, role = await require_org(session, user, org_slug)
    require_admin(role)
    key = (
        await session.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.org_id == org.id))
    ).scalar_one_or_none()
    if key is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "api key not found")
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
