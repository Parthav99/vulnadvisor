"""Ingest API: a real ``vulnadvisor`` report persists findings and returns the correct diff.

The reports here are built by the **actual engine** (``build_report`` over real ``score_match``
findings), so this exercises the same JSON the CLI emits — proving the platform and CLI never
diverge. Malformed / unsupported reports and cross-org keys are rejected.
"""

from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor.engine.scoring import score_match
from vulnadvisor.model import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    Dependency,
    DependencySource,
    EpssScore,
    MatchedAdvisory,
)
from vulnadvisor.output.json_report import build_report
from vulnadvisor_platform.models import Finding, Org

_HDR = "Authorization"


def _scored(name: str, advisory_id: str, *, version: str = "1.0") -> Any:
    matched = MatchedAdvisory(
        dependency=Dependency(
            name=name,
            raw_name=name,
            version=version,
            source=DependencySource.REQUIREMENTS_TXT,
            is_direct=True,
        ),
        advisory=Advisory(
            id=advisory_id,
            aliases=(f"CVE-2024-{abs(hash(advisory_id)) % 9999:04d}",),
            summary=f"{name} vulnerability",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            affected=(
                AffectedPackage(name=name, ranges=(AffectedRange(introduced="0", fixed="99"),)),
            ),
        ),
        epss=EpssScore(cve="CVE-2024-0001", probability=0.5, percentile=0.9),
        in_kev=True,
    )
    return score_match(matched)


def build_report_doc(specs: list[tuple[str, str]]) -> dict[str, Any]:
    """A real engine JSON report for the given ``(package, advisory_id)`` findings."""
    findings = [_scored(name, advisory_id) for name, advisory_id in specs]
    return build_report(findings, [], tool_version="1.0.3")


def _body(report: dict[str, Any], *, ref: str = "refs/heads/main", sha: str = "abc123") -> dict:
    return {"commit_sha": sha, "ref": ref, "report": report}


async def test_ingest_persists_findings_and_first_diff(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    report = build_report_doc([("jinja2", "GHSA-1"), ("flask", "GHSA-2")])
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body(report),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["summary"]["total"] == 2
    assert body["diff_summary"] == {
        "introduced": 2,
        "fixed": 0,
        "unchanged": 0,
        "previous_scan_id": None,
    }

    async with sessionmaker() as session:
        findings = (await session.execute(select(Finding))).scalars().all()
        assert {f.package for f in findings} == {"jinja2", "flask"}
        jinja = next(f for f in findings if f.package == "jinja2")
        assert jinja.payload["advisory"]["id"] == "GHSA-1"  # full finding stored verbatim
        assert jinja.band and jinja.priority > 0


async def test_ingest_second_scan_computes_diff(client: AsyncClient, seeded_key: str) -> None:
    headers = {_HDR: f"Bearer {seeded_key}"}
    first = build_report_doc([("jinja2", "GHSA-1"), ("flask", "GHSA-2")])
    await client.post("/v1/orgs/acme/repos/web/scans", headers=headers, json=_body(first, sha="c1"))

    second = build_report_doc([("jinja2", "GHSA-1"), ("requests", "GHSA-3")])
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans", headers=headers, json=_body(second, sha="c2")
    )
    assert resp.status_code == 201
    diff = resp.json()["diff_summary"]
    assert (diff["introduced"], diff["fixed"], diff["unchanged"]) == (1, 1, 1)
    assert diff["previous_scan_id"] is not None


async def test_ingest_diff_is_scoped_to_ref(client: AsyncClient, seeded_key: str) -> None:
    headers = {_HDR: f"Bearer {seeded_key}"}
    report = build_report_doc([("jinja2", "GHSA-1")])
    await client.post(
        "/v1/orgs/acme/repos/web/scans", headers=headers, json=_body(report, ref="refs/heads/main")
    )
    # A different ref has no baseline, so everything is "introduced".
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans",
        headers=headers,
        json=_body(report, ref="refs/heads/feature"),
    )
    diff = resp.json()["diff_summary"]
    assert diff["introduced"] == 1
    assert diff["previous_scan_id"] is None


async def test_ingest_empty_report_is_valid(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body(build_report_doc([])),
    )
    assert resp.status_code == 201
    assert resp.json()["summary"]["total"] == 0
    assert resp.json()["diff_summary"]["introduced"] == 0


async def test_ingest_requires_auth(client: AsyncClient) -> None:
    resp = await client.post("/v1/orgs/acme/repos/web/scans", json=_body(build_report_doc([])))
    assert resp.status_code == 401


async def test_ingest_unknown_org_is_404(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.post(
        "/v1/orgs/nope/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body(build_report_doc([])),
    )
    assert resp.status_code == 404


async def test_ingest_cross_org_key_is_403(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    # The seeded key belongs to "acme"; a second org must reject it.
    async with sessionmaker() as session:
        session.add(Org(slug="other", name="Other Inc"))
        await session.commit()
    resp = await client.post(
        "/v1/orgs/other/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body(build_report_doc([])),
    )
    assert resp.status_code == 403


async def test_ingest_rejects_unsupported_schema(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body({"schema_version": "0.9", "findings": []}),
    )
    assert resp.status_code == 422


async def test_ingest_rejects_missing_schema(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body({"findings": []}),
    )
    assert resp.status_code == 422


async def test_ingest_rejects_malformed_finding(client: AsyncClient, seeded_key: str) -> None:
    # schema_version is fine, but a finding is missing advisory/score.
    bad = {"schema_version": "1.0", "findings": [{"dependency": {"name": "x"}}]}
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body(bad),
    )
    assert resp.status_code == 422
