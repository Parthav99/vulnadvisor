"""POST /v1/scans — the CLI ``--upload`` target: org from the API key, repo from the body."""

from typing import Any

from _helpers import build_report_doc
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.models import Finding, Repository, Scan

_HDR = "Authorization"


def _body(report: dict[str, Any], *, repo: str = "web") -> dict:
    return {"repo": repo, "report": report}


async def test_upload_persists_under_keys_org(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    report = build_report_doc([("jinja2", "GHSA-1"), ("flask", "GHSA-2")])
    resp = await client.post(
        "/v1/scans", headers={_HDR: f"Bearer {seeded_key}"}, json=_body(report)
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["summary"]["total"] == 2
    assert body["diff_summary"]["introduced"] == 2

    # The repo was created under the key's org ("acme") with the body's name.
    async with sessionmaker() as session:
        repo = (
            await session.execute(select(Repository).where(Repository.name == "web"))
        ).scalar_one()
        findings = (
            (await session.execute(select(Finding).where(Finding.scan_id.isnot(None))))
            .scalars()
            .all()
        )
        assert {f.package for f in findings} == {"jinja2", "flask"}
        assert repo.name == "web"


async def test_upload_second_scan_diffs(client: AsyncClient, seeded_key: str) -> None:
    headers = {_HDR: f"Bearer {seeded_key}"}
    first = build_report_doc([("jinja2", "GHSA-1"), ("flask", "GHSA-2")])
    await client.post("/v1/scans", headers=headers, json=_body(first))
    second = build_report_doc([("jinja2", "GHSA-1"), ("requests", "GHSA-3")])
    resp = await client.post("/v1/scans", headers=headers, json=_body(second))
    assert resp.status_code == 201
    diff = resp.json()["diff_summary"]
    assert (diff["introduced"], diff["fixed"], diff["unchanged"]) == (1, 1, 1)


async def test_upload_requires_auth(client: AsyncClient) -> None:
    resp = await client.post("/v1/scans", json=_body(build_report_doc([])))
    assert resp.status_code == 401


async def test_upload_rejects_bad_schema(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.post(
        "/v1/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body({"schema_version": "0.9", "findings": []}),
    )
    assert resp.status_code == 422


async def test_upload_without_commit_ref_stores_null(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    # A bare local upload (no git) sends no commit/ref; both are stored as null (Task 12.2).
    resp = await client.post(
        "/v1/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body(build_report_doc([("jinja2", "GHSA-1")])),
    )
    assert resp.status_code == 201
    async with sessionmaker() as session:
        scan = (await session.execute(select(Scan))).scalar_one()
        assert scan.commit_sha is None
        assert scan.ref is None

    # The read API surfaces the nulls verbatim — no zeros anywhere.
    detail = await client.get(
        f"/v1/scans/{resp.json()['scan_id']}", headers={_HDR: f"Bearer {seeded_key}"}
    )
    assert detail.status_code == 200
    assert detail.json()["commit_sha"] is None
    assert detail.json()["ref"] is None


async def test_upload_placeholder_zeros_normalized_to_null(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    # Pre-12.2 CLIs sent forty zeros; the platform never stores that as fact.
    body = _body(build_report_doc([("jinja2", "GHSA-1")]))
    body["commit_sha"] = "0" * 40
    body["ref"] = "  "
    resp = await client.post("/v1/scans", headers={_HDR: f"Bearer {seeded_key}"}, json=body)
    assert resp.status_code == 201
    async with sessionmaker() as session:
        scan = (await session.execute(select(Scan))).scalar_one()
        assert scan.commit_sha is None
        assert scan.ref is None


async def test_null_ref_scans_diff_against_each_other(client: AsyncClient, seeded_key: str) -> None:
    # Local scans (null ref) form their own diff baseline, same as a named ref.
    headers = {_HDR: f"Bearer {seeded_key}"}
    await client.post(
        "/v1/scans", headers=headers, json=_body(build_report_doc([("jinja2", "GHSA-1")]))
    )
    resp = await client.post(
        "/v1/scans",
        headers=headers,
        json=_body(build_report_doc([("jinja2", "GHSA-1"), ("requests", "GHSA-3")])),
    )
    assert resp.status_code == 201
    diff = resp.json()["diff_summary"]
    assert (diff["introduced"], diff["fixed"], diff["unchanged"]) == (1, 0, 1)


async def test_upload_with_real_commit_ref_kept(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    body = _body(build_report_doc([("jinja2", "GHSA-1")]))
    body["commit_sha"] = "a" * 40
    body["ref"] = "refs/heads/main"
    resp = await client.post("/v1/scans", headers={_HDR: f"Bearer {seeded_key}"}, json=body)
    assert resp.status_code == 201
    async with sessionmaker() as session:
        scan = (await session.execute(select(Scan))).scalar_one()
        assert scan.commit_sha == "a" * 40
        assert scan.ref == "refs/heads/main"


async def test_upload_requires_repo(client: AsyncClient, seeded_key: str) -> None:
    # Missing/empty repo is a request-validation error.
    resp = await client.post(
        "/v1/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json={"repo": "", "report": build_report_doc([])},
    )
    assert resp.status_code == 422
