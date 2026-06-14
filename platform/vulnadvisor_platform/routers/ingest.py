"""Ingest API (Task 11.3): persist an uploaded ``vulnadvisor`` report and diff it vs the last scan.

This is the value spine: CI / the CLI / a self-hosted runner POSTs the JSON report it already
produced — **never source code**. The platform validates it against the schema, denormalizes the
findings for querying, and computes the introduced/fixed/unchanged diff against the previous scan on
the same ref. Auth is an org-scoped API key (the key's org must match the path org).
"""

from typing import Any

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnadvisor_platform.db import SessionDep
from vulnadvisor_platform.models import Finding, Org, Repository, Scan, ScanSource, ScanStatus
from vulnadvisor_platform.reports import (
    ReportValidationError,
    diff_finding_keys,
    parse_report,
    parse_suggestions,
)
from vulnadvisor_platform.schemas import (
    DiffSummary,
    IngestRequest,
    IngestResponse,
    ScanUploadRequest,
)
from vulnadvisor_platform.security import CurrentApiKey

router = APIRouter(tags=["ingest"])


def _clean_commit_sha(value: str | None) -> str | None:
    """Empty or placeholder ("0000…") SHAs become null — never stored and rendered as fact."""
    sha = (value or "").strip()
    if not sha or set(sha) == {"0"}:
        return None
    return sha


def _clean_ref(value: str | None) -> str | None:
    """Empty/whitespace refs become null."""
    ref = (value or "").strip()
    return ref or None


async def _store_scan(
    session: AsyncSession,
    org: Org,
    repo_name: str,
    *,
    commit_sha: str | None,
    ref: str | None,
    pr_number: int | None,
    source: ScanSource,
    report: dict[str, Any],
    suggestions: dict[str, Any] | None = None,
) -> IngestResponse:
    """Validate a report and persist it as a new scan + findings, returning the summary and diff.

    Shared by the path-scoped ingest endpoint and the key-scoped ``/v1/scans`` upload; the caller
    is responsible for authorizing the ``org``. Pure storage logic — no auth decisions here.
    Placeholder commit SHAs (all zeros, from pre-12.2 CLIs) are normalized to null on the way in.
    Optional ``suggestions`` (a ``fix --suggest-json`` document) is validated and stored on the scan
    for the PR review agent; a malformed one is rejected with the report's 422 semantics.
    """
    commit_sha = _clean_commit_sha(commit_sha)
    ref = _clean_ref(ref)
    try:
        parsed = parse_report(report)
        fixes = parse_suggestions(suggestions)
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
    # A null ref compares as IS NULL, so local scans diff against the previous local scan.
    previous = (
        await session.execute(
            select(Scan)
            .where(Scan.repo_id == repo.id, Scan.ref == ref)
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
        commit_sha=commit_sha,
        ref=ref,
        pr_number=pr_number,
        source=source.value,
        tool_version=parsed.tool_version,
        status=ScanStatus.COMPLETE.value,
        degraded_sources=parsed.degraded_sources,
        summary=parsed.summary,
        suggestions=fixes,
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
                finding_type=row.finding_type,
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

    return await _store_scan(
        session,
        org,
        repo_name,
        commit_sha=body.commit_sha,
        ref=body.ref,
        pr_number=body.pr_number,
        source=body.source,
        report=body.report,
        suggestions=body.suggestions,
    )


@router.post("/v1/scans", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def upload_scan(
    body: ScanUploadRequest, api_key: CurrentApiKey, session: SessionDep
) -> IngestResponse:
    """Upload a scan report with the org taken from the API key (the CLI ``--upload`` target).

    The repository is named in the body; it is created on first upload. The report is the exact
    ``vulnadvisor scan --format json`` document — source code is never sent.
    """
    org = await session.get(Org, api_key.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org not found")

    return await _store_scan(
        session,
        org,
        body.repo,
        commit_sha=body.commit_sha,
        ref=body.ref,
        pr_number=body.pr_number,
        source=body.source,
        report=body.report,
        suggestions=body.suggestions,
    )
