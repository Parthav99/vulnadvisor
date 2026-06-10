"""POST /v1/scans — the CLI ``--upload`` target: org from the API key, repo from the body."""

from typing import Any

from _helpers import build_report_doc
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.models import Finding, Repository

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


async def test_upload_requires_repo(client: AsyncClient, seeded_key: str) -> None:
    # Missing/empty repo is a request-validation error.
    resp = await client.post(
        "/v1/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json={"repo": "", "report": build_report_doc([])},
    )
    assert resp.status_code == 422
