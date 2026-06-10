"""Read API: orgs/repos/scans/findings/diff/trend, pagination, and strict tenant isolation."""

from datetime import UTC, datetime
from typing import Any

from _helpers import build_report_doc
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.models import Finding, Org, Repository, Scan
from vulnadvisor_platform.trends import summarize_tiers

_HDR = "Authorization"


def _auth(key: str) -> dict[str, str]:
    return {_HDR: f"Bearer {key}"}


async def _ingest(
    client: AsyncClient,
    key: str,
    specs: list[tuple[str, str]],
    *,
    ref: str = "refs/heads/main",
    sha: str = "s1",
    repo: str = "web",
) -> str:
    resp = await client.post(
        f"/v1/orgs/acme/repos/{repo}/scans",
        headers=_auth(key),
        json={"commit_sha": sha, "ref": ref, "report": build_report_doc(specs)},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["scan_id"]


# --- the sound trend categorization (pure) ------------------------------------------------------


def test_summarize_tiers_only_not_imported_is_deprioritized() -> None:
    totals = summarize_tiers(
        {
            "not-imported": 5,
            "imported": 2,
            "imported-and-called": 3,
            "dynamic-unknown": 1,
            "unknown": 4,
        }
    )
    assert totals.deprioritized == 5  # only the confidently-safe tier
    assert totals.actionable == 2 + 3 + 1 + 4  # everything else stays actionable (soundness)
    assert totals.reachable_called == 3


# --- orgs / repos -------------------------------------------------------------------------------


async def test_list_orgs_returns_membership(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.get("/v1/orgs", headers=_auth(seeded_key))
    assert resp.status_code == 200
    orgs = resp.json()
    assert [o["slug"] for o in orgs] == ["acme"]
    assert orgs[0]["role"] == "owner"


async def test_org_detail_counts(client: AsyncClient, seeded_key: str) -> None:
    await _ingest(client, seeded_key, [("jinja2", "GHSA-1")])
    resp = await client.get("/v1/orgs/acme", headers=_auth(seeded_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["repo_count"] == 1
    assert body["member_count"] == 1
    assert body["role"] == "owner"


async def test_list_and_get_repo(client: AsyncClient, seeded_key: str) -> None:
    await _ingest(client, seeded_key, [("jinja2", "GHSA-1")], repo="web")
    repos = (await client.get("/v1/orgs/acme/repos", headers=_auth(seeded_key))).json()
    assert [r["name"] for r in repos] == ["web"]
    assert repos[0]["scan_count"] == 1
    assert repos[0]["last_scan_at"] is not None

    detail = await client.get("/v1/orgs/acme/repos/web", headers=_auth(seeded_key))
    assert detail.status_code == 200
    assert detail.json()["name"] == "web"


# --- scans / findings / diff --------------------------------------------------------------------


async def test_list_scans_paginates(client: AsyncClient, seeded_key: str) -> None:
    for i in range(3):
        await _ingest(client, seeded_key, [("jinja2", "GHSA-1")], sha=f"c{i}")

    page1 = (
        await client.get("/v1/orgs/acme/repos/web/scans?limit=2", headers=_auth(seeded_key))
    ).json()
    assert len(page1["items"]) == 2
    assert page1["next_cursor"] is not None

    page2 = (
        await client.get(
            f"/v1/orgs/acme/repos/web/scans?limit=2&cursor={page1['next_cursor']}",
            headers=_auth(seeded_key),
        )
    ).json()
    assert len(page2["items"]) == 1
    assert page2["next_cursor"] is None

    seen = {item["id"] for item in page1["items"]} | {item["id"] for item in page2["items"]}
    assert len(seen) == 3  # every scan returned exactly once, no overlap


async def test_scan_detail_and_findings_filters(client: AsyncClient, seeded_key: str) -> None:
    scan_id = await _ingest(client, seeded_key, [("jinja2", "GHSA-1"), ("flask", "GHSA-2")])

    detail = await client.get(f"/v1/scans/{scan_id}", headers=_auth(seeded_key))
    assert detail.status_code == 200
    assert detail.json()["summary"]["total"] == 2

    findings = (await client.get(f"/v1/scans/{scan_id}/findings", headers=_auth(seeded_key))).json()
    assert findings["count"] == 2
    # priority-desc and each entry is the engine's finding object verbatim.
    priorities = [f["score"]["value"] for f in findings["findings"]]
    assert priorities == sorted(priorities, reverse=True)
    assert findings["findings"][0]["advisory"]["id"] in {"GHSA-1", "GHSA-2"}

    # Filters: a band that matches vs one that doesn't.
    band = findings["findings"][0]["score"]["band"]
    matched = (
        await client.get(f"/v1/scans/{scan_id}/findings?band={band}", headers=_auth(seeded_key))
    ).json()
    assert matched["count"] >= 1
    empty = (
        await client.get(
            f"/v1/scans/{scan_id}/findings?min_priority=1000", headers=_auth(seeded_key)
        )
    ).json()
    assert empty["count"] == 0


async def test_diff_two_scans(client: AsyncClient, seeded_key: str) -> None:
    first = await _ingest(client, seeded_key, [("jinja2", "GHSA-1"), ("flask", "GHSA-2")], sha="a")
    second = await _ingest(
        client, seeded_key, [("jinja2", "GHSA-1"), ("requests", "GHSA-3")], sha="b"
    )
    diff = (await client.get(f"/v1/scans/{first}/diff/{second}", headers=_auth(seeded_key))).json()
    assert {f["dependency"]["name"] for f in diff["introduced"]} == {"requests"}
    assert {f["dependency"]["name"] for f in diff["fixed"]} == {"flask"}
    assert diff["unchanged"] == 1


# --- trend (per-day, from each day's latest scan) -----------------------------------------------


async def test_repo_trend_per_day(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    async with sessionmaker() as session:
        org = (await session.execute(select(Org).where(Org.slug == "acme"))).scalar_one()
        repo = Repository(org_id=org.id, name="trendrepo")
        session.add(repo)
        await session.flush()

        day1 = Scan(
            repo_id=repo.id,
            commit_sha="d1",
            ref="refs/heads/main",
            tool_version="1",
            degraded_sources=[],
            summary={},
            created_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
        )
        day2 = Scan(
            repo_id=repo.id,
            commit_sha="d2",
            ref="refs/heads/main",
            tool_version="1",
            degraded_sources=[],
            summary={},
            created_at=datetime(2026, 6, 2, 12, 0, tzinfo=UTC),
        )
        session.add_all([day1, day2])
        await session.flush()

        def _finding(scan_id: Any, sid: str, tier: str) -> Finding:
            return Finding(
                scan_id=scan_id,
                advisory_id=sid,
                package=sid,
                version="1",
                tier=tier,
                band="low",
                priority=1.0,
                payload={},
            )

        session.add_all(
            [
                _finding(day1.id, "A1", "not-imported"),
                _finding(day1.id, "A2", "imported"),
                _finding(day2.id, "B1", "imported-and-called"),
                _finding(day2.id, "B2", "not-imported"),
            ]
        )
        await session.commit()

    resp = await client.get(
        "/v1/orgs/acme/repos/trendrepo/trend?window=90d", headers=_auth(seeded_key)
    )
    assert resp.status_code == 200
    points = resp.json()["points"]
    assert points == [
        {"date": "2026-06-01", "actionable": 1, "deprioritized": 1, "reachable_called": 0},
        {"date": "2026-06-02", "actionable": 1, "deprioritized": 1, "reachable_called": 1},
    ]


async def test_trend_rejects_bad_window(client: AsyncClient, seeded_key: str) -> None:
    await _ingest(client, seeded_key, [("jinja2", "GHSA-1")])
    resp = await client.get("/v1/orgs/acme/repos/web/trend?window=oops", headers=_auth(seeded_key))
    assert resp.status_code == 400


# --- tenant isolation ---------------------------------------------------------------------------


async def test_cannot_read_other_orgs_detail(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    async with sessionmaker() as session:
        session.add(Org(slug="other", name="Other Inc"))
        await session.commit()
    # The user is not a member of "other": 404, and it never appears in their org list.
    assert (await client.get("/v1/orgs/other", headers=_auth(seeded_key))).status_code == 404
    orgs = (await client.get("/v1/orgs", headers=_auth(seeded_key))).json()
    assert "other" not in {o["slug"] for o in orgs}


async def test_cannot_read_other_orgs_scan(
    client: AsyncClient,
    seeded_key: str,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    async with sessionmaker() as session:
        other = Org(slug="other", name="Other Inc")
        session.add(other)
        await session.flush()
        repo = Repository(org_id=other.id, name="secret")
        session.add(repo)
        await session.flush()
        scan = Scan(
            repo_id=repo.id,
            commit_sha="x",
            ref="refs/heads/main",
            tool_version="1",
            degraded_sources=[],
            summary={},
        )
        session.add(scan)
        await session.commit()
        other_scan_id = scan.id

    # Our user belongs only to "acme"; the cross-tenant scan must be invisible (404, not 403).
    resp = await client.get(f"/v1/scans/{other_scan_id}", headers=_auth(seeded_key))
    assert resp.status_code == 404
