"""Retention compaction: dry-run == live, latest-per-ref always survives, idempotent re-runs."""

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.compact import (
    apply_compaction,
    build_parser,
    plan_compaction,
    run_compaction,
)
from vulnadvisor_platform.db import utcnow
from vulnadvisor_platform.models import Finding, Org, Repository, Scan


async def _seed_repo(session: AsyncSession) -> uuid.UUID:
    org = Org(slug="acme", name="Acme Inc")
    session.add(org)
    await session.flush()
    repo = Repository(org_id=org.id, name="web")
    session.add(repo)
    await session.flush()
    return repo.id


async def _scan_with_findings(
    session: AsyncSession,
    repo_id: uuid.UUID,
    created_at: datetime,
    *,
    ref: str | None,
    findings: int,
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
    for i in range(findings):
        session.add(
            Finding(
                scan_id=scan.id,
                advisory_id=f"GHSA-{i}",
                package=f"pkg{i}",
                version="1.0",
                tier="imported",
                band="high",
                priority=75.0,
                payload={"advisory": {"id": f"GHSA-{i}"}, "in_kev": False},
            )
        )
    return scan.id


async def _payloads_by_scan(session: AsyncSession, scan_id: uuid.UUID) -> list[dict[str, object]]:
    rows = (
        await session.execute(select(Finding.payload).where(Finding.scan_id == scan_id))
    ).scalars()
    return list(rows)


async def test_dry_run_reports_exactly_what_live_mode_deletes(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    now = utcnow()
    main_ref = "refs/heads/main"
    async with sessionmaker() as session:
        repo_id = await _seed_repo(session)
        # main ref: two prunable (old + superseded), one old-but-recent-enough, one latest.
        s100 = await _scan_with_findings(
            session, repo_id, now - timedelta(days=100), ref=main_ref, findings=2
        )
        s95 = await _scan_with_findings(
            session, repo_id, now - timedelta(days=95), ref=main_ref, findings=1
        )
        s50 = await _scan_with_findings(
            session, repo_id, now - timedelta(days=50), ref=main_ref, findings=1
        )
        s5 = await _scan_with_findings(
            session, repo_id, now - timedelta(days=5), ref=main_ref, findings=1
        )
        # null-ref (local scans): the older one is prunable; the latest survives despite its age.
        n120 = await _scan_with_findings(
            session, repo_id, now - timedelta(days=120), ref=None, findings=1
        )
        n110 = await _scan_with_findings(
            session, repo_id, now - timedelta(days=110), ref=None, findings=1
        )
        await session.commit()

    async with sessionmaker() as session:
        plan = await plan_compaction(session, older_than_days=60)
        planned_ids = set(plan.scan_ids)
        assert planned_ids == {s100, s95, n120}
        assert plan.total_findings == 4  # 2 + 1 + 1, hand-computed

        pruned = await apply_compaction(session, plan)
        assert pruned == plan.total_findings  # dry-run reported exactly what live deleted

    async with sessionmaker() as session:
        # Pruned scans: payloads emptied; denormalized finding rows still exist.
        for scan_id in (s100, s95, n120):
            payloads = await _payloads_by_scan(session, scan_id)
            assert payloads and all(p == {} for p in payloads), scan_id
        # Survivors keep their full payloads: latest-per-ref (any age) and anything newer
        # than the cutoff.
        for scan_id in (s50, s5, n110):
            payloads = await _payloads_by_scan(session, scan_id)
            assert payloads and all(p != {} for p in payloads), scan_id

        # Idempotent: a re-run (the cron case) plans nothing and prunes nothing.
        replan = await plan_compaction(session, older_than_days=60)
        assert replan.scans == ()
        assert await apply_compaction(session, replan) == 0


async def test_latest_per_ref_survives_even_with_aggressive_cutoff(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    now = utcnow()
    async with sessionmaker() as session:
        repo_id = await _seed_repo(session)
        only_main = await _scan_with_findings(
            session, repo_id, now - timedelta(days=400), ref="refs/heads/main", findings=2
        )
        only_local = await _scan_with_findings(
            session, repo_id, now - timedelta(days=400), ref=None, findings=1
        )
        await session.commit()

    async with sessionmaker() as session:
        plan = await plan_compaction(session, older_than_days=1)
        assert plan.scans == ()  # each scan is the latest on its ref: never pruned
        await apply_compaction(session, plan)
        assert all(p != {} for p in await _payloads_by_scan(session, only_main))
        assert all(p != {} for p in await _payloads_by_scan(session, only_local))


async def test_run_compaction_dry_run_by_default(
    sessionmaker: async_sessionmaker[AsyncSession],
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = utcnow()
    async with sessionmaker() as session:
        repo_id = await _seed_repo(session)
        old = await _scan_with_findings(
            session, repo_id, now - timedelta(days=100), ref="refs/heads/main", findings=2
        )
        await _scan_with_findings(
            session, repo_id, now - timedelta(days=1), ref="refs/heads/main", findings=1
        )
        await session.commit()

    exit_code = await run_compaction(days=60, apply=False, sessionmaker=sessionmaker)
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "dry-run: nothing pruned" in out
    assert "1 scans / 2 finding payloads" in out
    async with sessionmaker() as session:
        assert all(p != {} for p in await _payloads_by_scan(session, old))  # untouched

    exit_code = await run_compaction(days=60, apply=True, sessionmaker=sessionmaker)
    assert exit_code == 0
    assert "pruned 2 finding payloads across 1 scans" in capsys.readouterr().out
    async with sessionmaker() as session:
        assert all(p == {} for p in await _payloads_by_scan(session, old))


def test_parser_defaults_and_validation() -> None:
    parser = build_parser()
    args = parser.parse_args([])
    assert args.days == 90
    assert args.apply is False
    args = parser.parse_args(["--days", "30", "--apply"])
    assert args.days == 30
    assert args.apply is True
    with pytest.raises(SystemExit):
        parser.parse_args(["--days", "0"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--days", "soon"])
