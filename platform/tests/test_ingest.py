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


def _suggestions_doc() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "tool_version": "9.9.9",
        "fixes": [
            {
                "finding_id": "app.py:5:command-injection",
                "file": "app.py",
                "line": 5,
                "cwe": "CWE-78",
                "kind": "command-injection",
                "title": "OS command injection",
                "tier": "CONFIRMED-FLOW",
                "flow": "run -> os.system (app.py:5)",
                "rationale": "Quote the argument.",
                "confidence": "high",
                "diff": "--- a/app.py\n+++ b/app.py\n@@ -5 +5 @@\n-x\n+y\n",
            }
        ],
    }


async def test_ingest_stores_validated_suggestions(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    from vulnadvisor_platform.models import Scan

    body = _body(build_report_doc([("jinja2", "GHSA-1")]))
    body["suggestions"] = _suggestions_doc()
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans", headers={_HDR: f"Bearer {seeded_key}"}, json=body
    )
    assert resp.status_code == 201

    async with sessionmaker() as session:
        scan = (await session.execute(select(Scan))).scalars().one()
        assert len(scan.suggestions) == 1
        stored = scan.suggestions[0]
        assert stored["finding_id"] == "app.py:5:command-injection"
        assert stored["line"] == 5 and stored["diff"]


async def test_ingest_rejects_bad_suggestions_schema(client: AsyncClient, seeded_key: str) -> None:
    body = _body(build_report_doc([]))
    body["suggestions"] = {"schema_version": "9.9", "tool_version": "1", "fixes": []}
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans", headers={_HDR: f"Bearer {seeded_key}"}, json=body
    )
    assert resp.status_code == 422
    assert "schema_version" in resp.json()["detail"]


async def test_ingest_without_suggestions_stores_empty(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    from vulnadvisor_platform.models import Scan

    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body(build_report_doc([("jinja2", "GHSA-1")])),
    )
    assert resp.status_code == 201
    async with sessionmaker() as session:
        scan = (await session.execute(select(Scan))).scalars().one()
        assert scan.suggestions == []


def test_parse_suggestions_is_defensive() -> None:
    from vulnadvisor_platform.reports import ReportValidationError, parse_suggestions

    assert parse_suggestions(None) == []
    # Valid plus malformed entries: the good one survives, the rest are dropped silently.
    doc = {
        "schema_version": "1.0",
        "tool_version": "1",
        "fixes": [
            {"finding_id": "a:1:x", "file": "a.py", "line": 1, "diff": "d", "confidence": "bogus"},
            {"finding_id": "b:2:y", "file": "b.py", "diff": "d"},  # missing line
            {"finding_id": "c", "file": "c.py", "line": 0, "diff": "d"},  # non-positive line
            "not an object",
            {"file": "d.py", "line": 1, "diff": "d"},  # missing finding_id
        ],
    }
    rows = parse_suggestions(doc)
    assert len(rows) == 1
    assert rows[0]["finding_id"] == "a:1:x"
    assert rows[0]["confidence"] == "medium"  # unknown confidence coerced to a safe default
    assert rows[0]["title"] == ""  # absent string fields default to empty
    assert (
        rows[0]["provenance"] == "model"
    )  # absent provenance defaults to "model" (Task 19.3/19.4)

    for bad in ([], "x", {"schema_version": "1.0", "tool_version": "1", "fixes": "no"}):
        try:
            parse_suggestions(bad)
        except ReportValidationError:
            continue
        raise AssertionError(f"expected ReportValidationError for {bad!r}")


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


async def test_ingest_accepts_fused_provenance_field(client: AsyncClient, seeded_key: str) -> None:
    """A 1.2 code finding carrying the additive ``provenance`` array (Task 21.4 fusion) ingests and
    survives verbatim in the stored payload, so the dashboard reads it back unchanged."""
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
            "rationale": "CWE-78; CONFIRMED-FLOW",
            "cvss_known": False,
        },
        "fix": {"direction": "Avoid shell=True.", "has_fix": False},
        "provenance": ["vulnadvisor", "semgrep-oss"],
    }
    report = {
        "schema_version": "1.2",
        "tool": {"name": "vulnadvisor", "version": "2.3.0"},
        "degraded_sources": [],
        "summary": {"total": 1, "by_band": {"critical": 1}},
        "findings": [code_finding],
    }
    resp = await client.post(
        "/v1/orgs/acme/repos/web/scans",
        headers={_HDR: f"Bearer {seeded_key}"},
        json=_body(report, sha="fused1"),
    )
    assert resp.status_code == 201
    scan_id = resp.json()["scan_id"]

    findings = (
        await client.get(f"/v1/scans/{scan_id}/findings", headers={_HDR: f"Bearer {seeded_key}"})
    ).json()["findings"]
    assert findings[0]["provenance"] == ["vulnadvisor", "semgrep-oss"]


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
