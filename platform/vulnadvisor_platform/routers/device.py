"""Device-flow login (Task 14.1): ``vulnadvisor login`` without key copy-paste.

RFC 8628-shaped three-legged flow:

1. ``POST /v1/device/code`` (unauthenticated, rate-limited per requester IP): mints a grant —
   a short human-typable ``user_code`` plus a high-entropy ``device_code`` (only its SHA-256
   hash is stored, like API keys).
2. ``POST /v1/device/approve`` (session or Bearer auth): a logged-in member binds the grant to
   one of their orgs on the dashboard's ``/activate`` page.
3. ``POST /v1/device/token`` (unauthenticated): the CLI polls with its ``device_code``. Pending
   grants answer ``authorization_pending`` (HTTP 400, RFC error shape); an approved grant mints
   the org-scoped API key *at poll time* — the plaintext secret exists only in this one response,
   never at rest — and the grant is consumed. Any later poll with the same code is rejected.
"""

import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from vulnadvisor_platform.access import require_org
from vulnadvisor_platform.config import SettingsDep
from vulnadvisor_platform.db import SessionDep, utcnow
from vulnadvisor_platform.models import ApiKey, DeviceGrant, Org
from vulnadvisor_platform.schemas import (
    DeviceApproveRequest,
    DeviceApproveResponse,
    DeviceCodeRequest,
    DeviceCodeResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
)
from vulnadvisor_platform.security import CurrentUser, generate_api_key, hash_key

router = APIRouter(tags=["device"])

# Grant lifetime and the polling interval advertised to the CLI.
GRANT_TTL_SECONDS = 900
POLL_INTERVAL_SECONDS = 5

# Rate limit on unauthenticated code minting: at most N grants per requester IP per window.
RATE_LIMIT_MAX_CODES = 10
RATE_LIMIT_WINDOW_SECONDS = 60

# User-code alphabet: unambiguous uppercase (no 0/O, 1/I/L) so the code survives being read
# aloud or retyped. 8 characters over 31 symbols ≈ 39.6 bits — plenty for a 15-minute,
# rate-limited, single-use code.
_CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
_CODE_LENGTH = 8


def _generate_user_code() -> str:
    """A human-typable code like ``XK7M-2PQ9`` (canonical form: uppercase, one hyphen)."""
    chars = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))
    return f"{chars[:4]}-{chars[4:]}"


def normalize_user_code(raw: str) -> str:
    """Canonicalize user input: uppercase, drop spaces/hyphens, re-insert the display hyphen."""
    stripped = "".join(ch for ch in raw.upper() if ch.isalnum())
    if len(stripped) != _CODE_LENGTH:
        return ""  # never matches a stored code
    return f"{stripped[:4]}-{stripped[4:]}"


def _as_aware(value: datetime) -> datetime:
    """Treat naive datetimes as UTC (SQLite round-trips tz-aware columns as naive)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _token_error(error: str) -> JSONResponse:
    """An RFC 8628 token-endpoint error: HTTP 400 with a machine-readable ``error`` code."""
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": error})


@router.post(
    "/v1/device/code", response_model=DeviceCodeResponse, status_code=status.HTTP_201_CREATED
)
async def create_device_code(
    body: DeviceCodeRequest, request: Request, session: SessionDep, settings: SettingsDep
) -> DeviceCodeResponse:
    """Mint a new device grant (unauthenticated; rate-limited per requester IP)."""
    requester_ip = request.client.host if request.client is not None else None

    if requester_ip is not None:
        window_start = utcnow() - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)
        recent = (
            await session.execute(
                select(func.count())
                .select_from(DeviceGrant)
                .where(
                    DeviceGrant.requester_ip == requester_ip,
                    DeviceGrant.created_at > window_start,
                )
            )
        ).scalar_one()
        if recent >= RATE_LIMIT_MAX_CODES:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many device-code requests; try again in a minute",
            )

    device_code = secrets.token_urlsafe(32)
    user_code = _generate_user_code()
    grant = DeviceGrant(
        user_code=user_code,
        device_code_hash=hash_key(device_code),
        client_name=body.client_name,
        requester_ip=requester_ip,
        expires_at=utcnow() + timedelta(seconds=GRANT_TTL_SECONDS),
    )
    session.add(grant)
    await session.commit()

    verification_uri = settings.dashboard_url.rstrip("/") + "/activate"
    return DeviceCodeResponse(
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=f"{verification_uri}?code={user_code}",
        expires_in=GRANT_TTL_SECONDS,
        interval=POLL_INTERVAL_SECONDS,
    )


@router.post("/v1/device/approve", response_model=DeviceApproveResponse)
async def approve_device_code(
    body: DeviceApproveRequest, user: CurrentUser, session: SessionDep
) -> DeviceApproveResponse:
    """Approve a pending grant for one of the caller's orgs (dashboard ``/activate``)."""
    org, _role = await require_org(session, user, body.org_slug)

    user_code = normalize_user_code(body.user_code)
    grant = (
        await session.execute(select(DeviceGrant).where(DeviceGrant.user_code == user_code))
    ).scalar_one_or_none()
    if grant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device code not found")
    if grant.approved_at is not None or grant.consumed_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "device code already used")
    if _as_aware(grant.expires_at) <= utcnow():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "device code expired")

    grant.org_id = org.id
    grant.approved_by = user.id
    grant.approved_at = utcnow()
    await session.commit()
    return DeviceApproveResponse(
        user_code=grant.user_code, org_slug=org.slug, client_name=grant.client_name
    )


@router.post(
    "/v1/device/token",
    response_model=DeviceTokenResponse,
    responses={400: {"description": "authorization_pending / expired_token / invalid_grant"}},
)
async def poll_device_token(
    body: DeviceTokenRequest, session: SessionDep
) -> DeviceTokenResponse | JSONResponse:
    """The CLI polls for its key. Single-use: a consumed or unknown code is ``invalid_grant``."""
    grant = (
        await session.execute(
            select(DeviceGrant).where(DeviceGrant.device_code_hash == hash_key(body.device_code))
        )
    ).scalar_one_or_none()
    if grant is None or grant.consumed_at is not None:
        return _token_error("invalid_grant")
    if _as_aware(grant.expires_at) <= utcnow():
        return _token_error("expired_token")
    if grant.approved_at is None or grant.org_id is None:
        return _token_error("authorization_pending")

    org = await session.get(Org, grant.org_id)
    if org is None:  # org deleted between approval and poll
        return _token_error("invalid_grant")

    # Mint the org-scoped key now, so the plaintext secret never sits in the database: it exists
    # only in this response. Consume the grant in the same transaction (reuse is rejected).
    secret, prefix, digest = generate_api_key()
    label = grant.client_name or "device"
    key = ApiKey(
        org_id=org.id,
        name=f"device login ({label})",
        hash=digest,
        prefix=prefix,
        created_by=grant.approved_by,
    )
    session.add(key)
    await session.flush()
    grant.api_key_id = key.id
    grant.consumed_at = utcnow()
    await session.commit()

    return DeviceTokenResponse(access_token=secret, token_type="bearer", org_slug=org.slug)
