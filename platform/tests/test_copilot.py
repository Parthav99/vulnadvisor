"""Copilot backend (Task 15.1): encrypted BYO key, service-token grant, daily cap, tenancy."""

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.app import app
from vulnadvisor_platform.config import Settings, get_settings
from vulnadvisor_platform.copilot import (
    CopilotKeyError,
    decrypt_api_key,
    encrypt_api_key,
    key_hint,
    validate_anthropic_key,
)
from vulnadvisor_platform.models import ApiKey, Membership, Org, Role, User
from vulnadvisor_platform.security import generate_api_key

PLAINTEXT = "sk-ant-api03-test-0123456789abcdefXYZ"
SERVICE_TOKEN = "svc-test-token"


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _service(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}", "X-Copilot-Service": SERVICE_TOKEN}


def _override_settings(**kwargs: Any) -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(
        copilot_service_token=SERVICE_TOKEN, **kwargs
    )


async def _seed_actor(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    login: str,
    org_slug: str | None,
    role: str = Role.MEMBER.value,
    github_user_id: int = 0,
) -> str:
    """Create a user (optionally a member of ``org_slug``) and return their API key."""
    full, prefix, digest = generate_api_key()
    async with sessionmaker() as session:
        user = User(login=login, github_user_id=github_user_id)
        session.add(user)
        await session.flush()
        org_id = None
        if org_slug is not None:
            org = (
                await session.execute(select(Org).where(Org.slug == org_slug))
            ).scalar_one_or_none()
            if org is None:
                org = Org(slug=org_slug, name=org_slug.title(), github_org_id=github_user_id + 500)
                session.add(org)
                await session.flush()
            org_id = org.id
            session.add(Membership(user_id=user.id, org_id=org.id, role=role))
        # The key row needs an org; reuse the user's org or park it on acme (key auth resolves
        # the *user*, and read access is decided by memberships, not the key's org).
        if org_id is None:
            org_id = (await session.execute(select(Org.id).where(Org.slug == "acme"))).scalar_one()
        session.add(
            ApiKey(
                org_id=org_id, name=f"{login}-key", hash=digest, prefix=prefix, created_by=user.id
            )
        )
        await session.commit()
    return full


# --- settings: store encrypted, never returned --------------------------------------------------


async def test_set_key_stores_ciphertext_and_returns_hint_only(
    client: AsyncClient, seeded_key: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    _override_settings()
    resp = await client.put(
        "/v1/orgs/acme/settings/copilot-key",
        headers=_auth(seeded_key),
        json={"api_key": PLAINTEXT},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["byo_key_set"] is True
    assert body["key_hint"] == f"…{PLAINTEXT[-4:]}"
    assert PLAINTEXT not in resp.text  # the key never appears in the response

    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
    assert org.copilot_key_ciphertext is not None
    assert PLAINTEXT not in org.copilot_key_ciphertext  # encrypted at rest, not encoded
    settings = Settings()
    assert decrypt_api_key(settings.secret_key, org.copilot_key_ciphertext) == PLAINTEXT


async def test_key_never_returned_by_any_user_endpoint(
    client: AsyncClient, seeded_key: str
) -> None:
    """After storing a key, sweep every org-facing read surface for the plaintext."""
    _override_settings()
    await client.put(
        "/v1/orgs/acme/settings/copilot-key",
        headers=_auth(seeded_key),
        json={"api_key": PLAINTEXT},
    )
    for path in (
        "/v1/orgs/acme/settings/copilot",
        "/v1/orgs/acme",
        "/v1/orgs",
        "/v1/me",
        "/v1/orgs/acme/keys",
        "/v1/orgs/acme/analytics/overview",
    ):
        resp = await client.get(path, headers=_auth(seeded_key))
        assert resp.status_code == 200, path
        assert PLAINTEXT not in resp.text, path


async def test_settings_roundtrip_and_delete(client: AsyncClient, seeded_key: str) -> None:
    _override_settings()
    before = (await client.get("/v1/orgs/acme/settings/copilot", headers=_auth(seeded_key))).json()
    assert before == {"byo_key_set": False, "key_hint": None, "daily_cap": 50, "used_today": 0}

    await client.put(
        "/v1/orgs/acme/settings/copilot-key",
        headers=_auth(seeded_key),
        json={"api_key": PLAINTEXT},
    )
    after = (await client.get("/v1/orgs/acme/settings/copilot", headers=_auth(seeded_key))).json()
    assert after["byo_key_set"] is True

    cleared = await client.delete("/v1/orgs/acme/settings/copilot-key", headers=_auth(seeded_key))
    assert cleared.status_code == 204
    again = await client.delete("/v1/orgs/acme/settings/copilot-key", headers=_auth(seeded_key))
    assert again.status_code == 204  # idempotent
    final = (await client.get("/v1/orgs/acme/settings/copilot", headers=_auth(seeded_key))).json()
    assert final["byo_key_set"] is False and final["key_hint"] is None


async def test_key_format_rejected(client: AsyncClient, seeded_key: str) -> None:
    _override_settings()
    for bad in ("not-an-anthropic-key", "sk-ant-x", "sk-ant-" + "a b" * 10):
        resp = await client.put(
            "/v1/orgs/acme/settings/copilot-key",
            headers=_auth(seeded_key),
            json={"api_key": bad},
        )
        assert resp.status_code == 422, bad


async def test_member_cannot_manage_key_nonmember_gets_404(
    client: AsyncClient, seeded_key: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    _override_settings()
    member_key = await _seed_actor(
        sessionmaker,
        login="mallory-member",
        org_slug="acme",
        role=Role.MEMBER.value,
        github_user_id=2,
    )
    outsider_key = await _seed_actor(
        sessionmaker,
        login="oscar-outsider",
        org_slug="globex",
        role=Role.OWNER.value,
        github_user_id=3,
    )

    # Plain member: may read settings, may not set/clear the key.
    ok = await client.get("/v1/orgs/acme/settings/copilot", headers=_auth(member_key))
    assert ok.status_code == 200
    put = await client.put(
        "/v1/orgs/acme/settings/copilot-key",
        headers=_auth(member_key),
        json={"api_key": PLAINTEXT},
    )
    assert put.status_code == 403
    delete = await client.delete("/v1/orgs/acme/settings/copilot-key", headers=_auth(member_key))
    assert delete.status_code == 403

    # Non-member: the org does not exist for them (no existence leak).
    for method, path, kwargs in (
        ("GET", "/v1/orgs/acme/settings/copilot", {}),
        ("PUT", "/v1/orgs/acme/settings/copilot-key", {"json": {"api_key": PLAINTEXT}}),
        ("DELETE", "/v1/orgs/acme/settings/copilot-key", {}),
    ):
        resp = await client.request(method, path, headers=_auth(outsider_key), **kwargs)
        assert resp.status_code == 404, (method, path)


# --- grant: service token + caller session, cap enforced -----------------------------------------


async def test_grant_requires_service_token(client: AsyncClient, seeded_key: str) -> None:
    _override_settings()
    no_token = await client.post("/v1/orgs/acme/copilot/grant", headers=_auth(seeded_key))
    assert no_token.status_code == 403
    wrong = await client.post(
        "/v1/orgs/acme/copilot/grant",
        headers={**_auth(seeded_key), "X-Copilot-Service": "wrong"},
    )
    assert wrong.status_code == 403


async def test_grant_disabled_when_unconfigured(client: AsyncClient, seeded_key: str) -> None:
    # Default Settings: no copilot_service_token → the endpoint is off entirely.
    resp = await client.post(
        "/v1/orgs/acme/copilot/grant",
        headers={**_auth(seeded_key), "X-Copilot-Service": ""},
    )
    assert resp.status_code == 503


async def test_grant_platform_fallback_then_org_key(client: AsyncClient, seeded_key: str) -> None:
    _override_settings()
    fallback = await client.post("/v1/orgs/acme/copilot/grant", headers=_service(seeded_key))
    assert fallback.status_code == 200
    assert fallback.json() == {"key_source": "platform", "api_key": None, "remaining_today": 49}

    await client.put(
        "/v1/orgs/acme/settings/copilot-key",
        headers=_auth(seeded_key),
        json={"api_key": PLAINTEXT},
    )
    byo = (await client.post("/v1/orgs/acme/copilot/grant", headers=_service(seeded_key))).json()
    assert byo["key_source"] == "org"
    assert byo["api_key"] == PLAINTEXT  # decrypted only here, behind the service token


async def test_grant_cross_org_is_404_even_with_service_token(
    client: AsyncClient, seeded_key: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """The service token alone never grants access — the *caller's* membership scopes the org."""
    _override_settings()
    outsider_key = await _seed_actor(
        sessionmaker,
        login="oscar-outsider",
        org_slug="globex",
        role=Role.OWNER.value,
        github_user_id=3,
    )
    resp = await client.post("/v1/orgs/acme/copilot/grant", headers=_service(outsider_key))
    assert resp.status_code == 404
    own_org = await client.post("/v1/orgs/globex/copilot/grant", headers=_service(outsider_key))
    assert own_org.status_code == 200


async def test_daily_cap_enforced_and_reported(client: AsyncClient, seeded_key: str) -> None:
    _override_settings(copilot_daily_cap=3)
    remaining = []
    for _ in range(3):
        resp = await client.post("/v1/orgs/acme/copilot/grant", headers=_service(seeded_key))
        assert resp.status_code == 200
        remaining.append(resp.json()["remaining_today"])
    assert remaining == [2, 1, 0]

    capped = await client.post("/v1/orgs/acme/copilot/grant", headers=_service(seeded_key))
    assert capped.status_code == 429

    usage = (await client.get("/v1/orgs/acme/settings/copilot", headers=_auth(seeded_key))).json()
    assert usage == {"byo_key_set": False, "key_hint": None, "daily_cap": 3, "used_today": 3}


async def test_corrupted_ciphertext_is_a_loud_500(
    client: AsyncClient, seeded_key: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """A key that can no longer be decrypted must fail loudly, never silently fall back."""
    _override_settings()
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        org.copilot_key_ciphertext = "not-a-fernet-token"
        org.copilot_key_hint = "…dead"
        await session.commit()
    resp = await client.post("/v1/orgs/acme/copilot/grant", headers=_service(seeded_key))
    assert resp.status_code == 500
    assert "re-save" in resp.json()["detail"]


# --- pure helpers --------------------------------------------------------------------------------


def test_encrypt_decrypt_roundtrip_and_tamper() -> None:
    token = encrypt_api_key("secret-a", PLAINTEXT)
    assert decrypt_api_key("secret-a", token) == PLAINTEXT
    with pytest.raises(CopilotKeyError):
        decrypt_api_key("secret-b", token)  # different SECRET_KEY cannot decrypt
    with pytest.raises(CopilotKeyError):
        decrypt_api_key("secret-a", token[:-2] + "zz")


def test_validate_anthropic_key_rules() -> None:
    assert validate_anthropic_key(f"  {PLAINTEXT} ") == PLAINTEXT
    for bad in ("", "sk-other-key-123456", "sk-ant-short", "sk-ant-with space-0123456789"):
        with pytest.raises(ValueError):
            validate_anthropic_key(bad)


def test_key_hint_is_last_four() -> None:
    assert key_hint(PLAINTEXT) == f"…{PLAINTEXT[-4:]}"
    assert PLAINTEXT[:-4] not in key_hint(PLAINTEXT)
