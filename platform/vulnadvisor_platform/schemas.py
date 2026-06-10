"""Pydantic v2 request/response models for the API surface (Tasks 11.2–11.4)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from vulnadvisor_platform.models import ScanSource


class HealthResponse(BaseModel):
    """Payload for ``GET /healthz``."""

    status: str
    version: str


class OrgMembershipOut(BaseModel):
    """One org the authenticated user belongs to, with their role."""

    org_slug: str
    org_name: str
    role: str


class MeResponse(BaseModel):
    """Payload for ``GET /v1/me`` — the authenticated user and their orgs/roles."""

    id: uuid.UUID
    login: str
    email: str | None
    avatar_url: str | None
    orgs: list[OrgMembershipOut]


class IngestRequest(BaseModel):
    """Body for ``POST /v1/orgs/{org}/repos/{repo}/scans`` — a CLI/CI report upload."""

    commit_sha: str
    ref: str
    pr_number: int | None = None
    source: ScanSource = ScanSource.CI
    report: dict[str, Any]


class DiffSummary(BaseModel):
    """Counts of findings introduced/fixed/unchanged vs the previous scan on the same ref."""

    introduced: int
    fixed: int
    unchanged: int
    previous_scan_id: uuid.UUID | None


class IngestResponse(BaseModel):
    """Result of an ingest: the new scan id, its summary, and the diff vs the previous scan."""

    scan_id: uuid.UUID
    summary: dict[str, Any]
    diff_summary: DiffSummary


# --- Read API (Task 11.4) -----------------------------------------------------------------------


class OrgOut(BaseModel):
    """An org the authenticated user belongs to, with their role."""

    id: uuid.UUID
    slug: str
    name: str
    plan: str
    role: str


class OrgDetailOut(OrgOut):
    """Org detail with counts."""

    repo_count: int
    member_count: int


class RepoOut(BaseModel):
    """A repository with scan activity counts."""

    id: uuid.UUID
    name: str
    default_branch: str
    is_private: bool
    scan_count: int
    last_scan_at: datetime | None


class ScanListItem(BaseModel):
    """A scan as it appears in a list (no per-finding detail)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    commit_sha: str
    ref: str
    pr_number: int | None
    source: str
    status: str
    tool_version: str
    summary: dict[str, Any]
    created_at: datetime


class ScanPage(BaseModel):
    """A page of scans with an opaque cursor for the next page (keyset pagination)."""

    items: list[ScanListItem]
    next_cursor: str | None


class ScanDetailOut(BaseModel):
    """Full scan detail."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    repo_id: uuid.UUID
    commit_sha: str
    ref: str
    pr_number: int | None
    source: str
    status: str
    tool_version: str
    degraded_sources: list[str]
    summary: dict[str, Any]
    created_at: datetime


class FindingsResponse(BaseModel):
    """Findings for a scan; each entry is the engine's JSON-report finding object verbatim."""

    scan_id: uuid.UUID
    count: int
    findings: list[dict[str, Any]]


class TrendPoint(BaseModel):
    """One day of the repo trend (from that day's latest scan)."""

    date: str
    actionable: int
    deprioritized: int
    reachable_called: int


class TrendResponse(BaseModel):
    """Per-day actionable/deprioritized/reachable-called counts over a window."""

    repo_id: uuid.UUID
    window_days: int
    points: list[TrendPoint]


class DiffResponse(BaseModel):
    """Findings introduced/fixed between two scans, plus the unchanged count."""

    from_scan_id: uuid.UUID
    to_scan_id: uuid.UUID
    introduced: list[dict[str, Any]]
    fixed: list[dict[str, Any]]
    unchanged: int
