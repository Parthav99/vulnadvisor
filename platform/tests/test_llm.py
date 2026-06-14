"""Server-side LLM proxy for ``vulnadvisor suggest`` (Task D1).

The endpoint authenticates with the org API key and runs the suggest-loop model call using the
org's BYO copilot key. The model call itself is monkeypatched (no network): we prove the trust +
cap shape, never the model. ``build_fix_client_for_key`` is patched in the *router* namespace, so
the real provider routing in :mod:`vulnadvisor.llm.client` stays unit-tested elsewhere.
"""

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor.llm.client import LLMError
from vulnadvisor_platform.app import app
from vulnadvisor_platform.config import Settings, get_settings
from vulnadvisor_platform.models import Org
from vulnadvisor_platform.routers import llm as llm_router

# A well-formed BYO Anthropic key (validated by the copilot PUT endpoint on store).
ORG_KEY = "sk-ant-api03-test-0123456789abcdefXYZ"


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _override_settings(**kwargs: Any) -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(**kwargs)


class _FakeClient:
    """A scripted :class:`LLMClient` that records its prompt and returns canned text or raises."""

    model = "fake-model"

    def __init__(self, captured: dict[str, Any], *, text: str = "MODEL OUTPUT") -> None:
        self._captured = captured
        self._text = text

    def complete(self, *, system: str, user: str) -> str:
        self._captured["system"] = system
        self._captured["user"] = user
        if self._text is None:
            raise LLMError("upstream model exploded")
        return self._text


def _patch_client(
    monkeypatch: pytest.MonkeyPatch, captured: dict[str, Any], *, text: str | None = "MODEL OUTPUT"
) -> None:
    """Patch the router's client builder to a fake; capture the key/model it was built with."""

    def fake_build(api_key: str, *, model: str | None = None) -> _FakeClient:
        captured["api_key"] = api_key
        captured["model"] = model
        return _FakeClient(captured, text=text)  # type: ignore[arg-type]

    monkeypatch.setattr(llm_router, "build_fix_client_for_key", fake_build)


async def _set_org_key(client: AsyncClient, seeded_key: str, *, key: str = ORG_KEY) -> None:
    """Store the org's BYO copilot key via the real settings endpoint (encrypts at rest)."""
    resp = await client.put(
        "/v1/orgs/acme/settings/copilot-key", headers=_auth(seeded_key), json={"api_key": key}
    )
    assert resp.status_code == 200


async def _used_today(client: AsyncClient, seeded_key: str) -> int:
    settings = await client.get("/v1/orgs/acme/settings/copilot", headers=_auth(seeded_key))
    return int(settings.json()["used_today"])


# --- no key -> graceful no-op --------------------------------------------------------------------


async def test_complete_without_byo_key_is_graceful_noop(
    client: AsyncClient, seeded_key: str
) -> None:
    _override_settings()
    resp = await client.post(
        "/v1/llm/complete", headers=_auth(seeded_key), json={"system": "s", "user": "u"}
    )
    assert resp.status_code == 200
    assert resp.json() == {"available": False, "text": None, "remaining_today": None}
    # A no-op must not consume a grant.
    assert await _used_today(client, seeded_key) == 0


# --- happy path: org key performs the call -------------------------------------------------------


async def test_complete_uses_org_key_and_consumes_one_grant(
    client: AsyncClient, seeded_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _override_settings()
    await _set_org_key(client, seeded_key)
    captured: dict[str, Any] = {}
    _patch_client(monkeypatch, captured)

    resp = await client.post(
        "/v1/llm/complete",
        headers=_auth(seeded_key),
        json={"system": "be helpful", "user": "fix this", "model": "claude-x"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is True
    assert body["text"] == "MODEL OUTPUT"
    assert body["remaining_today"] == 49  # default cap 50, one consumed
    # The decrypted BYO key (never the request) drove the call, with the requested model + prompt.
    assert captured["api_key"] == ORG_KEY
    assert captured["model"] == "claude-x"
    assert captured["system"] == "be helpful"
    assert captured["user"] == "fix this"
    assert await _used_today(client, seeded_key) == 1


async def test_complete_defaults_model_to_none(
    client: AsyncClient, seeded_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _override_settings()
    await _set_org_key(client, seeded_key)
    captured: dict[str, Any] = {}
    _patch_client(monkeypatch, captured)

    resp = await client.post(
        "/v1/llm/complete", headers=_auth(seeded_key), json={"system": "s", "user": "u"}
    )
    assert resp.status_code == 200
    assert captured["model"] is None  # provider default chosen downstream


# --- platform fallback key (zero-config) ---------------------------------------------------------

FALLBACK_KEY = "sk-or-v1-fallback-0123456789abcdef"
FALLBACK_MODEL = "deepseek/deepseek-r1:free"


async def test_complete_uses_fallback_key_when_org_has_none(
    client: AsyncClient, seeded_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _override_settings(copilot_fallback_api_key=FALLBACK_KEY, copilot_fallback_model=FALLBACK_MODEL)
    captured: dict[str, Any] = {}
    _patch_client(monkeypatch, captured)

    resp = await client.post(
        "/v1/llm/complete", headers=_auth(seeded_key), json={"system": "s", "user": "u"}
    )

    assert resp.status_code == 200
    assert resp.json()["available"] is True
    # The platform fallback key + its configured free model drove the call (no org key needed).
    assert captured["api_key"] == FALLBACK_KEY
    assert captured["model"] == FALLBACK_MODEL
    assert await _used_today(client, seeded_key) == 1


async def test_complete_org_key_wins_over_fallback(
    client: AsyncClient, seeded_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _override_settings(copilot_fallback_api_key=FALLBACK_KEY, copilot_fallback_model=FALLBACK_MODEL)
    await _set_org_key(client, seeded_key)
    captured: dict[str, Any] = {}
    _patch_client(monkeypatch, captured)

    resp = await client.post(
        "/v1/llm/complete", headers=_auth(seeded_key), json={"system": "s", "user": "u"}
    )
    assert resp.status_code == 200
    # The org's own key takes precedence; the fallback is only a last resort.
    assert captured["api_key"] == ORG_KEY


async def test_complete_request_model_overrides_fallback_model(
    client: AsyncClient, seeded_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _override_settings(copilot_fallback_api_key=FALLBACK_KEY, copilot_fallback_model=FALLBACK_MODEL)
    captured: dict[str, Any] = {}
    _patch_client(monkeypatch, captured)

    resp = await client.post(
        "/v1/llm/complete",
        headers=_auth(seeded_key),
        json={"system": "s", "user": "u", "model": "explicit/model"},
    )
    assert resp.status_code == 200
    assert captured["model"] == "explicit/model"


# --- cap -----------------------------------------------------------------------------------------


async def test_complete_enforces_daily_cap(
    client: AsyncClient, seeded_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _override_settings(copilot_daily_cap=2)
    await _set_org_key(client, seeded_key)
    _patch_client(monkeypatch, {})

    remaining = []
    for _ in range(2):
        resp = await client.post(
            "/v1/llm/complete", headers=_auth(seeded_key), json={"system": "s", "user": "u"}
        )
        assert resp.status_code == 200
        remaining.append(resp.json()["remaining_today"])
    assert remaining == [1, 0]

    capped = await client.post(
        "/v1/llm/complete", headers=_auth(seeded_key), json={"system": "s", "user": "u"}
    )
    assert capped.status_code == 429
    assert await _used_today(client, seeded_key) == 2


# --- model failure does not burn the grant -------------------------------------------------------


async def test_complete_model_error_is_502_and_keeps_the_grant(
    client: AsyncClient, seeded_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _override_settings()
    await _set_org_key(client, seeded_key)
    _patch_client(monkeypatch, {}, text=None)  # the fake raises LLMError

    resp = await client.post(
        "/v1/llm/complete", headers=_auth(seeded_key), json={"system": "s", "user": "u"}
    )
    assert resp.status_code == 502
    assert "model call failed" in resp.json()["detail"]
    # A failed call must not consume budget.
    assert await _used_today(client, seeded_key) == 0


# --- corrupted ciphertext fails loudly -----------------------------------------------------------


async def test_complete_corrupted_ciphertext_is_a_loud_500(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _override_settings()
    _patch_client(monkeypatch, {})
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        org.copilot_key_ciphertext = "not-a-fernet-token"
        org.copilot_key_hint = "…dead"
        await session.commit()

    resp = await client.post(
        "/v1/llm/complete", headers=_auth(seeded_key), json={"system": "s", "user": "u"}
    )
    assert resp.status_code == 500
    assert "re-save" in resp.json()["detail"]


# --- auth ----------------------------------------------------------------------------------------


async def test_complete_requires_an_api_key(client: AsyncClient) -> None:
    resp = await client.post("/v1/llm/complete", json={"system": "s", "user": "u"})
    assert resp.status_code == 401
