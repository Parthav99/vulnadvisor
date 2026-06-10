"""API-key management: issue (secret shown once), list (no secret), revoke, and role checks."""

from _helpers import build_report_doc
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.models import ApiKey, Membership, Org, Role, User
from vulnadvisor_platform.security import generate_api_key


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _scan_body() -> dict:
    return {
        "commit_sha": "c1",
        "ref": "refs/heads/main",
        "report": build_report_doc([("jinja2", "GHSA-1")]),
    }


async def test_create_list_revoke_key(client: AsyncClient, seeded_key: str) -> None:
    created = await client.post(
        "/v1/orgs/acme/keys", headers=_auth(seeded_key), json={"name": "ci-upload"}
    )
    assert created.status_code == 201
    body = created.json()
    secret = body["secret"]
    assert "hash" not in body  # never expose the hash
    assert body["prefix"] and secret.startswith(body["prefix"])

    # The freshly minted secret authorizes an ingest.
    ok = await client.post(
        "/v1/orgs/acme/repos/web/scans", headers=_auth(secret), json=_scan_body()
    )
    assert ok.status_code == 201

    # Listing shows metadata only — never the secret or hash.
    listed = (await client.get("/v1/orgs/acme/keys", headers=_auth(seeded_key))).json()
    assert any(k["name"] == "ci-upload" for k in listed)
    assert all("hash" not in k and "secret" not in k for k in listed)

    # Revoke it.
    revoke = await client.delete(f"/v1/orgs/acme/keys/{body['id']}", headers=_auth(seeded_key))
    assert revoke.status_code == 204

    # The revoked secret no longer authenticates.
    denied = await client.post(
        "/v1/orgs/acme/repos/web/scans", headers=_auth(secret), json=_scan_body()
    )
    assert denied.status_code == 401

    listed_after = (await client.get("/v1/orgs/acme/keys", headers=_auth(seeded_key))).json()
    revoked = next(k for k in listed_after if k["id"] == body["id"])
    assert revoked["revoked_at"] is not None


async def test_api_keys_alias_create_list_revoke(client: AsyncClient, seeded_key: str) -> None:
    """The /v1/orgs/{org}/api-keys alias (used by the dashboard) works like /keys."""
    created = await client.post(
        "/v1/orgs/acme/api-keys", headers=_auth(seeded_key), json={"name": "dash-key"}
    )
    assert created.status_code == 201
    key_id = created.json()["id"]

    listed = (await client.get("/v1/orgs/acme/api-keys", headers=_auth(seeded_key))).json()
    assert any(k["id"] == key_id for k in listed)

    revoke = await client.delete(f"/v1/orgs/acme/api-keys/{key_id}", headers=_auth(seeded_key))
    assert revoke.status_code == 204


async def test_revoke_unknown_key_is_404(client: AsyncClient, seeded_key: str) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    resp = await client.delete(f"/v1/orgs/acme/keys/{missing}", headers=_auth(seeded_key))
    assert resp.status_code == 404


async def test_create_key_requires_admin(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    member_secret, prefix, digest = generate_api_key()
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        member = User(login="member", github_user_id=2)
        session.add(member)
        await session.flush()
        session.add(Membership(user_id=member.id, org_id=org.id, role=Role.MEMBER.value))
        session.add(
            ApiKey(org_id=org.id, name="m", hash=digest, prefix=prefix, created_by=member.id)
        )
        await session.commit()

    # A plain member can list but not create.
    assert (await client.get("/v1/orgs/acme/keys", headers=_auth(member_secret))).status_code == 200
    resp = await client.post(
        "/v1/orgs/acme/keys", headers=_auth(member_secret), json={"name": "nope"}
    )
    assert resp.status_code == 403


async def test_keys_other_org_is_404(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    async with sessionmaker() as session:
        session.add(Org(slug="other", name="Other Inc"))
        await session.commit()
    resp = await client.get("/v1/orgs/other/keys", headers=_auth(seeded_key))
    assert resp.status_code == 404
