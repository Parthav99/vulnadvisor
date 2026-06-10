"""Ingest API (Task 11.3): persist an uploaded ``vulnadvisor`` report and diff it vs the last scan.

This is the value spine: CI / the CLI / a self-hosted runner POSTs the JSON report it already
produced — **never source code**. The platform validates it against the schema, denormalizes the
findings for querying, and computes the introduced/fixed/unchanged diff against the previous scan on
the same ref. Auth is an org-scoped API key (the key's org must match the path org).
"""

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from vulnadvisor_platform.db import SessionDep
from vulnadvisor_platform.models import Finding, Org, Repository, Scan, ScanStatus
from vulnadvisor_platform.reports import ReportValidationError, diff_finding_keys, parse_report
from vulnadvisor_platform.schemas import DiffSummary, IngestRequest, IngestResponse
from vulnadvisor_platform.security import CurrentApiKey

router = APIRouter(tags=["ingest"])


@router.post(
    "/v1/orgs/{org_slug}/repos/{repo_name}/scans",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
)
async def ingest_scan(
    org_slug: str,
    repo_name: str,
    body: IngestRequest,
    api_key: CurrentApiKey,
    session: SessionDep,
) -> IngestResponse:
    """Validate + store a report as a new scan, returning the scan id, summary, and diff."""
    org = (await session.execute(select(Org).where(Org.slug == org_slug))).scalar_one_or_none()
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org not found")
    if api_key.org_id != org.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API key does not belong to this org")

    try:
        parsed = parse_report(body.report)
    except ReportValidationError as exc:
        # 422 (unprocessable) — same status FastAPI uses for request-body validation failures.
        raise HTTPException(422, str(exc)) from exc

    # Upsert the repository so CI can publish without a prior GitHub App install (11.6).
    repo = (
        await session.execute(
            select(Repository).where(Repository.org_id == org.id, Repository.name == repo_name)
        )
    ).scalar_one_or_none()
    if repo is None:
        repo = Repository(org_id=org.id, name=repo_name)
        session.add(repo)
        await session.flush()

    # The previous scan on this ref (before inserting the new one) is the diff baseline.
    previous = (
        await session.execute(
            select(Scan)
            .where(Scan.repo_id == repo.id, Scan.ref == body.ref)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    previous_keys: list[tuple[str, str]] = []
    previous_scan_id = None
    if previous is not None:
        previous_scan_id = previous.id
        rows = (
            await session.execute(
                select(Finding.package, Finding.advisory_id).where(Finding.scan_id == previous.id)
            )
        ).all()
        previous_keys = [(package, advisory_id) for package, advisory_id in rows]

    scan = Scan(
        repo_id=repo.id,
        commit_sha=body.commit_sha,
        ref=body.ref,
        pr_number=body.pr_number,
        source=body.source.value,
        tool_version=parsed.tool_version,
        status=ScanStatus.COMPLETE.value,
        degraded_sources=parsed.degraded_sources,
        summary=parsed.summary,
    )
    session.add(scan)
    await session.flush()

    for row in parsed.findings:
        session.add(
            Finding(
                scan_id=scan.id,
                advisory_id=row.advisory_id,
                package=row.package,
                version=row.version,
                tier=row.tier,
                band=row.band,
                priority=row.priority,
                payload=row.payload,
            )
        )

    counts = diff_finding_keys(previous_keys, [row.key for row in parsed.findings])
    await session.commit()

    return IngestResponse(
        scan_id=scan.id,
        summary=parsed.summary,
        diff_summary=DiffSummary(
            introduced=counts.introduced,
            fixed=counts.fixed,
            unchanged=counts.unchanged,
            previous_scan_id=previous_scan_id,
        ),
    )
