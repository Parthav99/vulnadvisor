"""Analytics endpoints: hand-computed aggregates over a seeded multi-repo, multi-scan org,
plus tenant isolation (cross-org 404) on all four endpoints."""

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.analytics import resolution_episodes
from vulnadvisor_platform.db import utcnow
from vulnadvisor_platform.models import Finding, Org, Repository, Scan

_HDR = "Authorization"


def _auth(key: str) -> dict[str, str]:
    return {_HDR: f"Bearer {key}"}


async def _acme_id(session: AsyncSession) -> uuid.UUID:
    return (await session.execute(select(Org.id).where(Org.slug == "acme"))).scalar_one()


async def _repo(session: AsyncSession, org_id: uuid.UUID, name: str) -> uuid.UUID:
    repo = Repository(org_id=org_id, name=name)
    session.add(repo)
    await session.flush()
    return repo.id


async def _scan(
    session: AsyncSession,
    repo_id: uuid.UUID,
    created_at: datetime,
    *,
    ref: str | None = "refs/heads/main",
) -> uuid.UUID:
    scan = Scan(
        repo_id=repo_id,
        commit_sha=None,
        ref=ref,
        tool_version="1",
        degraded_sources=[],
        summary={},
        created_at=created_at,
    )
    session.add(scan)
    await session.flush()
    return scan.id


def _finding(
    scan_id: uuid.UUID,
    package: str,
    advisory_id: str,
    *,
    tier: str = "imported",
    band: str = "high",
    priority: float = 75.0,
    in_kev: bool = False,
) -> Finding:
    return Finding(
        scan_id=scan_id,
        advisory_id=advisory_id,
        package=package,
        version="1.0",
        tier=tier,
        band=band,
        priority=priority,
        payload={"in_kev": in_kev},
    )


# --- pure resolution-episode derivation -----------------------------------------------------------


def test_resolution_episodes_reappearance_makes_two_episodes() -> None:
    t0 = datetime(2026, 6, 1, tzinfo=UTC)
    key = ("yaml", "GHSA-1")
    timeline: list[tuple[datetime, dict[tuple[str, str], str]]] = [
        (t0, {key: "high"}),
        (t0 + timedelta(days=1), {}),  # fixed after 1 day
        (t0 + timedelta(days=3), {key: "high"}),  # regression
        (t0 + timedelta(days=5), {}),  # fixed again after 2 days
    ]
    episodes = resolution_episodes(timeline)
    assert [(e.band, e.days) for e in episodes] == [("high", 1.0), ("high", 2.0)]


def test_resolution_episodes_unresolved_yields_nothing() -> None:
    t0 = datetime(2026, 6, 1, tzinfo=UTC)
    key = ("yaml", "GHSA-1")
    timeline = [(t0, {key: "high"}), (t0 + timedelta(days=2), {key: "high"})]
    assert resolution_episodes(timeline) == []


# --- overview -------------------------------------------------------------------------------------


async def test_overview_aggregates_latest_scan_per_repo(
    client: AsyncClient, seeded_key: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    now = utcnow()
    async with sessionmaker() as session:
        org_id = await _acme_id(session)
        web = await _repo(session, org_id, "web")
        api = await _repo(session, org_id, "api")
        await _repo(session, org_id, "empty")  # no scans at all

        # Superseded scan: nothing from it may count (it has an extra KEV critical).
        old = await _scan(session, web, now - timedelta(days=2))
        session.add(_finding(old, "oldpkg", "GHSA-OLD", band="critical", in_kev=True))

        latest_web = await _scan(session, web, now - timedelta(days=1))
        session.add_all(
            [
                _finding(
                    latest_web,
                    "jinja2",
                    "GHSA-A",
                    tier="imported-and-called",
                    band="critical",
                    priority=95.0,
                    in_kev=True,
                ),
                _finding(latest_web, "flask", "GHSA-B", tier="imported", band="high"),
                _finding(
                    latest_web, "yaml", "GHSA-C", tier="not-imported", band="low", priority=20.0
                ),
            ]
        )
        latest_api = await _scan(session, api, now - timedelta(hours=1))
        session.add(
            _finding(
                latest_api,
                "requests",
                "GHSA-D",
                tier="dynamic-unknown",
                band="medium",
                priority=50.0,
                in_kev=True,
            )
        )
        await session.commit()

    resp = await client.get("/v1/orgs/acme/analytics/overview", headers=_auth(seeded_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["repo_count"] == 3
    assert body["total_findings"] == 4  # the superseded scan's finding is excluded
    assert body["by_tier"] == {
        "imported-and-called": 1,
        "imported": 1,
        "dynamic-unknown": 1,
        "not-imported": 1,
    }
    assert body["by_band"] == {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0}
    assert body["actionable"] == 3  # everything except not-imported (soundness)
    assert body["deprioritized"] == 1
    assert body["reachable_called"] == 1
    assert body["kev_count"] == 2  # jinja2 + requests; the superseded KEV finding is gone
    assert body["repos_at_risk"] == 2  # web + api; "empty" has no scans


async def test_overview_empty_org_is_all_zeros(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.get("/v1/orgs/acme/analytics/overview", headers=_auth(seeded_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["repo_count"] == 0
    assert body["total_findings"] == 0
    assert body["kev_count"] == 0
    assert body["repos_at_risk"] == 0
    assert body["by_band"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert body["by_tier"] == {
        "imported-and-called": 0,
        "imported": 0,
        "dynamic-unknown": 0,
        "not-imported": 0,
    }


# --- trend ----------------------------------------------------------------------------------------


async def test_org_trend_sums_each_days_latest_scan_per_repo(
    client: AsyncClient, seeded_key: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    now = utcnow()
    day1 = (now - timedelta(days=2)).replace(hour=9, minute=0)
    day2 = (now - timedelta(days=1)).replace(hour=9, minute=0)
    async with sessionmaker() as session:
        org_id = await _acme_id(session)
        repo1 = await _repo(session, org_id, "repo1")
        repo2 = await _repo(session, org_id, "repo2")

        s1 = await _scan(session, repo1, day1)
        session.add_all(
            [
                _finding(s1, "a1", "G1", tier="imported"),
                _finding(s1, "a2", "G2", tier="not-imported"),
            ]
        )
        # repo2 scans twice on day1: only the later scan counts for that day.
        s2_early = await _scan(session, repo2, day1)
        session.add_all([_finding(s2_early, f"x{i}", f"GX{i}", tier="imported") for i in range(5)])
        s2_late = await _scan(session, repo2, day1 + timedelta(hours=4))
        session.add_all(
            [
                _finding(s2_late, "b1", "G3", tier="imported-and-called"),
                _finding(s2_late, "b2", "G4", tier="imported"),
            ]
        )
        s3 = await _scan(session, repo1, day2)
        session.add(_finding(s3, "c1", "G5", tier="not-imported"))
        await session.commit()

    resp = await client.get("/v1/orgs/acme/analytics/trend?window=30d", headers=_auth(seeded_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["window_days"] == 30
    assert body["points"] == [
        {
            "date": day1.date().isoformat(),
            "actionable": 3,  # a1 + b1 + b2 (the early repo2 scan is superseded that day)
            "deprioritized": 1,  # a2
            "reachable_called": 1,  # b1
        },
        {
            "date": day2.date().isoformat(),
            "actionable": 0,
            "deprioritized": 1,
            "reachable_called": 0,
        },
    ]


async def test_org_trend_rejects_bad_window(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.get("/v1/orgs/acme/analytics/trend?window=oops", headers=_auth(seeded_key))
    assert resp.status_code == 400


# --- packages -------------------------------------------------------------------------------------


async def test_packages_ranked_by_max_priority(
    client: AsyncClient, seeded_key: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    now = utcnow()
    async with sessionmaker() as session:
        org_id = await _acme_id(session)
        web = await _repo(session, org_id, "web")
        api = await _repo(session, org_id, "api")

        # Superseded scan with a package that must NOT appear.
        old = await _scan(session, web, now - timedelta(days=2))
        session.add(_finding(old, "ghost", "GHSA-GONE", band="critical", priority=99.0))

        web_latest = await _scan(session, web, now - timedelta(days=1))
        api_latest = await _scan(session, api, now - timedelta(hours=2))
        session.add_all(
            [
                _finding(web_latest, "flask", "GHSA-F", band="critical", priority=95.0),
                _finding(web_latest, "jinja2", "GHSA-J1", band="critical", priority=90.0),
                _finding(api_latest, "jinja2", "GHSA-J2", band="high", priority=70.0),
                _finding(web_latest, "yaml", "GHSA-Y", band="info", priority=10.0),
            ]
        )
        await session.commit()

    resp = await client.get("/v1/orgs/acme/analytics/packages", headers=_auth(seeded_key))
    assert resp.status_code == 200
    packages = resp.json()["packages"]
    assert [p["package"] for p in packages] == ["flask", "jinja2", "yaml"]
    jinja = packages[1]
    assert jinja["max_priority"] == 90.0
    assert jinja["band"] == "critical"  # the band of its top-priority finding
    assert jinja["finding_count"] == 2
    assert jinja["repo_count"] == 2
    # Click-through target: the scan holding the package's top-priority finding.
    assert jinja["top_scan_id"] == str(web_latest)
    assert packages[0]["top_scan_id"] == str(web_latest)
    assert packages[0]["finding_count"] == 1
    assert packages[0]["repo_count"] == 1

    limited = (
        await client.get("/v1/orgs/acme/analytics/packages?limit=2", headers=_auth(seeded_key))
    ).json()["packages"]
    assert [p["package"] for p in limited] == ["flask", "jinja2"]


# --- resolution -----------------------------------------------------------------------------------


async def test_resolution_medians_per_band(
    client: AsyncClient, seeded_key: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    async with sessionmaker() as session:
        org_id = await _acme_id(session)
        web = await _repo(session, org_id, "web")

        def _on(scan_id: uuid.UUID, specs: list[tuple[str, str, str]]) -> list[Finding]:
            return [
                _finding(scan_id, pkg, adv, band=band, tier="imported") for pkg, adv, band in specs
            ]

        s0 = await _scan(session, web, t0)
        session.add_all(_on(s0, [("x", "GX", "high"), ("z", "GZ", "high"), ("y", "GY", "low")]))
        s1 = await _scan(session, web, t0 + timedelta(days=2))  # x fixed: 2 days (high)
        session.add_all(_on(s1, [("z", "GZ", "high"), ("y", "GY", "low")]))
        s2 = await _scan(session, web, t0 + timedelta(days=4))  # z fixed: 4 days (high)
        session.add_all(_on(s2, [("y", "GY", "low")]))
        s3 = await _scan(session, web, t0 + timedelta(days=5))  # y fixed: 5 days (low)
        session.add_all(_on(s3, []))

        # A different ref's timeline is independent: same key, alive in its latest scan ->
        # unresolved there, contributing nothing.
        f0 = await _scan(session, web, t0, ref="refs/heads/feature")
        session.add_all(_on(f0, [("x", "GX", "high")]))
        f1 = await _scan(session, web, t0 + timedelta(days=9), ref="refs/heads/feature")
        session.add_all(_on(f1, [("x", "GX", "high")]))
        await session.commit()

    resp = await client.get("/v1/orgs/acme/analytics/resolution", headers=_auth(seeded_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == {"resolved_count": 3, "median_days": 4.0}
    assert body["bands"]["high"] == {"resolved_count": 2, "median_days": 3.0}
    assert body["bands"]["low"] == {"resolved_count": 1, "median_days": 5.0}
    assert body["bands"]["critical"] == {"resolved_count": 0, "median_days": None}
    assert body["bands"]["medium"] == {"resolved_count": 0, "median_days": None}
    assert body["bands"]["info"] == {"resolved_count": 0, "median_days": None}


async def test_resolution_empty_org(client: AsyncClient, seeded_key: str) -> None:
    resp = await client.get("/v1/orgs/acme/analytics/resolution", headers=_auth(seeded_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == {"resolved_count": 0, "median_days": None}


# --- tenant isolation -----------------------------------------------------------------------------


async def test_cross_org_404_on_all_analytics_endpoints(
    client: AsyncClient, seeded_key: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    async with sessionmaker() as session:
        other = Org(slug="other", name="Other Inc")
        session.add(other)
        await session.flush()
        repo = await _repo(session, other.id, "secret")
        scan_id = await _scan(session, repo, utcnow())
        session.add(_finding(scan_id, "secretpkg", "GHSA-S", in_kev=True))
        await session.commit()

    paths: list[str] = [
        "/v1/orgs/other/analytics/overview",
        "/v1/orgs/other/analytics/trend",
        "/v1/orgs/other/analytics/packages",
        "/v1/orgs/other/analytics/resolution",
    ]
    for path in paths:
        resp = await client.get(path, headers=_auth(seeded_key))
        assert resp.status_code == 404, path


async def test_analytics_requires_auth(client: AsyncClient) -> None:
    resp = await client.get("/v1/orgs/acme/analytics/overview")
    assert resp.status_code == 401
