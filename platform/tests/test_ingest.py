"""Ingest API: a real ``vulnadvisor`` report persists findings and returns the correct diff.

The reports here are built by the **actual engine** (see ``_helpers``), so this exercises the same
JSON the CLI emits — proving the platform and CLI never diverge. Malformed / unsupported reports and
cross-org keys are rejected.
"""

import copy
from typing import Any

from _helpers import build_report_doc
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.models import Finding, Org

_HDR = "Authorization"


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


async def test_ingest_accepts_schema_1_0_1_1_and_1_2(client: AsyncClient, seeded_key: str) -> None:
    headers = {_HDR: f"Bearer {seeded_key}"}
    # The current CLI emits 1.2 (finding_type discriminator + code findings) — accepted.
    current = build_report_doc([("jinja2", "GHSA-1")])
    assert current["schema_version"] == "1.2"
    assert current["findings"][0]["finding_type"] == "dependency"
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans", headers=headers, json=_body(current, sha="c1")
    )
    assert resp.status_code == 201

    # A 1.1 report (no finding_type) — still accepted; treated as all-dependency findings.
    v11 = copy.deepcopy(current)
    v11["schema_version"] = "1.1"
    for finding in v11["findings"]:
        finding.pop("finding_type", None)
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans", headers=headers, json=_body(v11, sha="c2")
    )
    assert resp.status_code == 201

    # A pre-12.1 CLI emits 1.0 (no display_id) — still accepted; old reports keep ingesting.
    legacy = copy.deepcopy(v11)
    legacy["schema_version"] = "1.0"
    for finding in legacy["findings"]:
        finding["advisory"].pop("display_id", None)
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans", headers=headers, json=_body(legacy, sha="c3")
    )
    assert resp.status_code == 201
    assert resp.json()["summary"]["total"] == 1


async def test_ingest_accepts_code_finding(client: AsyncClient, seeded_key: str) -> None:
    """A schema-1.2 first-party (SAST) finding ingests and denormalizes to file + rule id."""
    code_finding = {
        "finding_type": "code",
        "rule": {"cwe": "CWE-78", "kind": "command-injection", "title": "OS command injection"},
        "location": {"file": "app/run.py", "line": 12, "column": 4},
        "flow": {
            "tier": "confirmed-flow",
            "reason": "tainted query parameter reaches os.system",
            "source": {"kind": "http-parameter", "file": "app/run.py", "line": 8},
            "sink": {"kind": "command-injection", "file": "app/run.py", "line": 12},
            "path": ["run -> os.system (app/run.py:12)"],
            "sanitizers": [],
        },
        "score": {
            "value": 95.0,
            "band": "critical",
            "verdict": "Fix now",
            "rationale": "CWE-78 base severity 9.5; CONFIRMED-FLOW",
            "cvss_known": False,
        },
        "fix": {"direction": "Avoid shell=True; pass an argument list.", "has_fix": False},
    }
    report = {
        "schema_version": "1.2",
        "tool": {"name": "vulnadvisor", "version": "2.0.0"},
        "degraded_sources": [],
        "summary": {"total": 1, "by_band": {"critical": 1}},
        "findings": [code_finding],
    }
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body(report, sha="code1"),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["summary"]["total"] == 1
    # The code finding is introduced (no prior scan on this ref).
    assert body["diff_summary"]["introduced"] == 1


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
