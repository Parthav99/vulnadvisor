"""Data-retention compaction (Task 13.3): prune finding payloads of old, superseded scans.

Free-tier Postgres (Neon) has tight storage, and the full engine JSON in ``findings.payload``
dominates it. This admin command empties the payload of findings whose scan is **both** older
than N days **and** not the latest scan on its (repo, ref) — so:

* the denormalized columns (package/advisory/tier/band/priority) always survive, keeping every
  trend/analytics number intact;
* the latest scan per (repo, ref) always keeps full payloads, so the dashboard's current view
  and the org overview (which reads ``payload['in_kev']`` from latest scans) are never degraded.

Scheduled-safe: idempotent (already-pruned findings drop out of the plan, so a cron re-run is a
no-op) and **dry-run by default** — live pruning requires ``--apply``::

    python -m vulnadvisor_platform.compact --days 90          # dry-run: report only
    python -m vulnadvisor_platform.compact --days 90 --apply  # prune
"""

import argparse
import asyncio
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import Text, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.db import get_sessionmaker, utcnow
from vulnadvisor_platform.models import Finding, Repository, Scan

# An empty JSON object's canonical text on both backends (json.dumps({}) on SQLite,
# jsonb::text on Postgres) — the marker for an already-pruned payload.
_EMPTY_PAYLOAD_TEXT = "{}"


@dataclass(frozen=True)
class ScanCompaction:
    """One scan whose finding payloads would be (or were) pruned."""

    scan_id: uuid.UUID
    repo_name: str
    ref: str | None
    created_at: datetime
    finding_count: int


@dataclass(frozen=True)
class CompactionPlan:
    """The exact set of scans/findings a live run will prune; what dry-run reports."""

    cutoff: datetime
    scans: tuple[ScanCompaction, ...]

    @property
    def scan_ids(self) -> list[uuid.UUID]:
        """Ids of every scan in the plan."""
        return [scan.scan_id for scan in self.scans]

    @property
    def total_findings(self) -> int:
        """Total finding payloads the plan prunes."""
        return sum(scan.finding_count for scan in self.scans)


async def plan_compaction(
    session: AsyncSession, *, older_than_days: int, now: datetime | None = None
) -> CompactionPlan:
    """Compute the prunable set: superseded-per-(repo, ref) scans older than the cutoff.

    A scan is superseded when a newer scan exists on the same (repo, ref) — the latest scan per
    ref is never pruned, regardless of age. Findings whose payload is already empty are excluded,
    so the plan (and a cron re-run) reports only real work.
    """
    cutoff = (now or utcnow()) - timedelta(days=older_than_days)
    rank = (
        func.row_number()
        .over(
            partition_by=(Scan.repo_id, Scan.ref),
            order_by=(Scan.created_at.desc(), Scan.id.desc()),
        )
        .label("rank")
    )
    ranked = select(Scan.id.label("scan_id"), rank).subquery()
    superseded = select(ranked.c.scan_id).where(ranked.c.rank > 1)

    rows = (
        await session.execute(
            select(Scan.id, Repository.name, Scan.ref, Scan.created_at, func.count())
            .join(Repository, Repository.id == Scan.repo_id)
            .join(Finding, Finding.scan_id == Scan.id)
            .where(
                Scan.id.in_(superseded),
                Scan.created_at < cutoff,
                Finding.payload.cast(Text) != _EMPTY_PAYLOAD_TEXT,
            )
            .group_by(Scan.id, Repository.name, Scan.ref, Scan.created_at)
            .order_by(Scan.created_at, Scan.id)
        )
    ).all()
    scans = tuple(
        ScanCompaction(
            scan_id=scan_id,
            repo_name=repo_name,
            ref=ref,
            created_at=created_at,
            finding_count=finding_count,
        )
        for scan_id, repo_name, ref, created_at, finding_count in rows
    )
    return CompactionPlan(cutoff=cutoff, scans=scans)


async def apply_compaction(session: AsyncSession, plan: CompactionPlan) -> int:
    """Prune exactly the plan's finding payloads (set to ``{}``); return the count pruned."""
    if not plan.scans:
        return 0
    where = (
        Finding.scan_id.in_(plan.scan_ids),
        Finding.payload.cast(Text) != _EMPTY_PAYLOAD_TEXT,
    )
    count = (
        await session.execute(select(func.count()).select_from(Finding).where(*where))
    ).scalar_one()
    await session.execute(
        update(Finding)
        .where(*where)
        .values(payload={})
        .execution_options(synchronize_session=False)
    )
    await session.commit()
    return count


async def run_compaction(
    *,
    days: int,
    apply: bool,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> int:
    """Plan (and with ``apply``, execute) a compaction, printing the report; returns exit code."""
    maker = sessionmaker if sessionmaker is not None else get_sessionmaker()
    async with maker() as session:
        plan = await plan_compaction(session, older_than_days=days)
        for scan in plan.scans:
            ref = scan.ref if scan.ref is not None else "(local)"
            print(
                f"prune: scan {scan.scan_id} repo={scan.repo_name} ref={ref} "
                f"created={scan.created_at.isoformat()} findings={scan.finding_count}"
            )
        print(
            f"plan: {len(plan.scans)} scans / {plan.total_findings} finding payloads "
            f"older than {days}d (cutoff {plan.cutoff.isoformat()})"
        )
        if not apply:
            print("dry-run: nothing pruned (pass --apply to prune)")
            return 0
        pruned = await apply_compaction(session, plan)
        print(f"pruned {pruned} finding payloads across {len(plan.scans)} scans")
    return 0


def _positive_days(value: str) -> int:
    try:
        days = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--days must be an integer") from exc
    if days < 1:
        raise argparse.ArgumentTypeError("--days must be >= 1")
    return days


def build_parser() -> argparse.ArgumentParser:
    """The ``compact`` admin command's argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m vulnadvisor_platform.compact",
        description=(
            "Prune finding payloads of scans older than N days (keeps denormalized rows and "
            "the latest scan per repo/ref). Dry-run by default."
        ),
    )
    parser.add_argument(
        "--days",
        type=_positive_days,
        default=90,
        help="prune payloads of superseded scans older than this many days (default: 90)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually prune; without this flag the command only reports the plan",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse args and run against the configured DATABASE_URL."""
    args = build_parser().parse_args(argv)
    return asyncio.run(run_compaction(days=args.days, apply=args.apply))


if __name__ == "__main__":
    raise SystemExit(main())
