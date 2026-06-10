"""Pydantic v2 response models for the API surface implemented in Task 11.2."""

import uuid

from pydantic import BaseModel


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
