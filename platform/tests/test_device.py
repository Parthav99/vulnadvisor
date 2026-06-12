"""Device-flow login (Task 14.1): grant lifecycle, expiry, reuse, rate limit, tenant scoping."""

import re
from datetime import UTC, datetime, timedelta

from _helpers import build_report_doc
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.models import ApiKey, DeviceGrant, Org
from vulnadvisor_platform.routers.device import (
    RATE_LIMIT_MAX_CODES,
    normalize_user_code,
)

_USER_CODE_RE = re.compile(r"^[2-9A-HJKMNP-Z]{4}-[2-9A-HJKMNP-Z]{4}$")


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def _mint_code(client: AsyncClient, client_name: str | None = "alice@laptop") -> dict:
    resp = await client.post("/v1/device/code", json={"client_name": client_name})
    assert resp.status_code == 201
    return resp.json()


async def _expire_grant(sessionmaker: async_sessionmaker[AsyncSession], user_code: str) -> None:
    async with sessionmaker() as session:
        grant = (
            await session.execute(select(DeviceGrant).where(DeviceGrant.user_code == user_code))
        ).scalar_one()
        grant.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()


async def test_full_grant_lifecycle(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """pending -> approve -> token mints a working key -> reuse rejected."""
    code = await _mint_code(client)
    assert _USER_CODE_RE.match(code["user_code"])
    assert code["verification_uri"].endswith("/activate")
    assert code["verification_uri_complete"].endswith(f"/activate?code={code['user_code']}")
    assert code["expires_in"] > 0 and code["interval"] > 0

    # Polling before approval reports authorization_pending (RFC 8628 error shape).
    pending = await client.post("/v1/device/token", json={"device_code": code["device_code"]})
    assert pending.status_code == 400
    assert pending.json() == {"error": "authorization_pending"}

    # Approval normalizes user input (lowercase, hyphen dropped).
    sloppy = code["user_code"].lower().replace("-", "")
    approved = await client.post(
        "/v1/device/approve",
        headers=_auth(seeded_key),
        json={"user_code": sloppy, "org_slug": "acme"},
    )
    assert approved.status_code == 200
    assert approved.json() == {
        "user_code": code["user_code"],
        "org_slug": "acme",
        "client_name": "alice@laptop",
    }

    # The next poll delivers the org-scoped key, exactly once.
    token = await client.post("/v1/device/token", json={"device_code": code["device_code"]})
    assert token.status_code == 200
    body = token.json()
    assert body["token_type"] == "bearer"
    assert body["org_slug"] == "acme"
    secret = body["access_token"]

    # The minted key authorizes a real upload (the key-scoped /v1/scans endpoint).
    upload = await client.post(
        "/v1/scans",
        headers=_auth(secret),
        json={"repo": "webapp", "report": build_report_doc([("jinja2", "GHSA-1")])},
    )
    assert upload.status_code == 201

    # Reuse of the device code is rejected: the grant is consumed.
    reuse = await client.post("/v1/device/token", json={"device_code": code["device_code"]})
    assert reuse.status_code == 400
    assert reuse.json() == {"error": "invalid_grant"}

    # The plaintext device code and API key are never at rest; the key is named for the device.
    async with sessionmaker() as session:
        grant = (
            await session.execute(
                select(DeviceGrant).where(DeviceGrant.user_code == code["user_code"])
            )
        ).scalar_one()
        assert grant.consumed_at is not None and grant.api_key_id is not None
        assert grant.device_code_hash != code["device_code"]
        key = await session.get(ApiKey, grant.api_key_id)
        assert key is not None
        assert key.name == "device login (alice@laptop)"
        assert key.hash != secret  # only the SHA-256 is stored


async def test_token_with_unknown_code_is_invalid_grant(client: AsyncClient) -> None:
    resp = await client.post("/v1/device/token", json={"device_code": "nope"})
    assert resp.status_code == 400
    assert resp.json() == {"error": "invalid_grant"}


async def test_expired_code_cannot_be_approved_or_redeemed(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    code = await _mint_code(client)
    await _expire_grant(sessionmaker, code["user_code"])

    token = await client.post("/v1/device/token", json={"device_code": code["device_code"]})
    assert token.status_code == 400
    assert token.json() == {"error": "expired_token"}

    approve = await client.post(
        "/v1/device/approve",
        headers=_auth(seeded_key),
        json={"user_code": code["user_code"], "org_slug": "acme"},
    )
    assert approve.status_code == 400


async def test_approve_twice_conflicts(client: AsyncClient, seeded_key: str) -> None:
    code = await _mint_code(client)
    body = {"user_code": code["user_code"], "org_slug": "acme"}
    first = await client.post("/v1/device/approve", headers=_auth(seeded_key), json=body)
    assert first.status_code == 200
    second = await client.post("/v1/device/approve", headers=_auth(seeded_key), json=body)
    assert second.status_code == 409


async def test_approve_unknown_code_is_404(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.post(
        "/v1/device/approve",
        headers=_auth(seeded_key),
        json={"user_code": "AAAA-AAAA", "org_slug": "acme"},
    )
    assert resp.status_code == 404


async def test_approve_requires_auth(client: AsyncClient) -> None:
    resp = await client.post(
        "/v1/device/approve", json={"user_code": "AAAA-AAAA", "org_slug": "acme"}
    )
    assert resp.status_code == 401


async def test_approve_non_member_org_is_404(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """Tenant scoping: a code can only be bound to an org the approver belongs to."""
    async with sessionmaker() as session:
        session.add(Org(slug="other", name="Other Inc"))
        await session.commit()
    code = await _mint_code(client)
    resp = await client.post(
        "/v1/device/approve",
        headers=_auth(seeded_key),
        json={"user_code": code["user_code"], "org_slug": "other"},
    )
    assert resp.status_code == 404


async def test_code_minting_is_rate_limited(client: AsyncClient) -> None:
    """At most RATE_LIMIT_MAX_CODES grants per requester IP per window; the next is 429."""
    for _ in range(RATE_LIMIT_MAX_CODES):
        resp = await client.post("/v1/device/code", json={})
        assert resp.status_code == 201
    blocked = await client.post("/v1/device/code", json={})
    assert blocked.status_code == 429


def test_normalize_user_code() -> None:
    assert normalize_user_code("xk7m-2pq9") == "XK7M-2PQ9"
    assert normalize_user_code("  xk7m 2pq9 ") == "XK7M-2PQ9"
    assert normalize_user_code("XK7M2PQ9") == "XK7M-2PQ9"
    assert normalize_user_code("short") == ""
    assert normalize_user_code("") == ""
    assert normalize_user_code("way-too-long-code-1234") == ""
