"""Pydantic v2 request/response models for the API surface (Tasks 11.2–11.3)."""

import uuid
from typing import Any

from pydantic import BaseModel

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
