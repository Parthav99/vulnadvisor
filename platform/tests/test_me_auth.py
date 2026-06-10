"""The ``/v1/me`` auth round-trip: 401 without a valid key, the user + orgs with one."""

from httpx import AsyncClient


async def test_me_requires_a_bearer_key(client: AsyncClient) -> None:
    resp = await client.get("/v1/me")
    assert resp.status_code == 401


async def test_me_rejects_unknown_key(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.get("/v1/me", headers={"Authorization": "Bearer va_dead.notarealkey"})
    assert resp.status_code == 401


async def test_me_rejects_non_bearer_scheme(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.get("/v1/me", headers={"Authorization": f"Basic {seeded_key}"})
    assert resp.status_code == 401


async def test_me_returns_user_and_orgs(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.get("/v1/me", headers={"Authorization": f"Bearer {seeded_key}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["login"] == "octocat"
    assert body["email"] == "octocat@example.com"
    assert body["orgs"] == [{"org_slug": "acme", "org_name": "Acme Inc", "role": "owner"}]
