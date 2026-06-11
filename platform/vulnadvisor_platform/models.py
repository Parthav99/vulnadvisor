"""SQLAlchemy 2.x models for the platform — the data model from ``docs/platform-design.md``.

Tenant boundary is the ``org``; every read path is org-scoped (enforced at the query layer). The
JSON columns (``payload``/``summary``/``degraded_sources``) hold the engine's own report objects so
the platform and CLI never diverge. String columns (role/source/status/tier/band) are validated at
the API boundary via the enums below rather than DB enum types, to keep migrations simple.
"""

import enum
import uuid
from datetime import datetime
from typing import Annotated, Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from vulnadvisor_platform.db import Base, JSONType, utcnow

# Reusable annotated column types (SQLAlchemy "annotated declarative"); mypy-clean and shared.
UuidPk = Annotated[uuid.UUID, mapped_column(primary_key=True, default=uuid.uuid4)]
CreatedAt = Annotated[datetime, mapped_column(DateTime(timezone=True), default=utcnow)]


class Role(enum.StrEnum):
    """A user's role within an org."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class ScanSource(enum.StrEnum):
    """Where a scan report came from."""

    CI = "ci"
    RUNNER = "runner"
    CLOUD = "cloud"
    PR = "pr"


class ScanStatus(enum.StrEnum):
    """Lifecycle of a scan record."""

    PENDING = "pending"
    COMPLETE = "complete"
    FAILED = "failed"


class Org(Base):
    """A billing/tenant boundary."""

    __tablename__ = "orgs"

    id: Mapped[UuidPk]
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    github_org_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    plan: Mapped[str] = mapped_column(String(32), default="free")
    created_at: Mapped[CreatedAt]


class User(Base):
    """A person, identified by their GitHub account."""

    __tablename__ = "users"

    id: Mapped[UuidPk]
    github_user_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    login: Mapped[str] = mapped_column(String(100))
    email: Mapped[str | None] = mapped_column(String(320))
    avatar_url: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[CreatedAt]


class Membership(Base):
    """A user's access to an org, with a role."""

    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "org_id", name="uq_membership_user_org"),)

    id: Mapped[UuidPk]
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(16), default=Role.MEMBER.value)
    created_at: Mapped[CreatedAt]


class Repository(Base):
    """A repository under an org."""

    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_repo_org_name"),)

    id: Mapped[UuidPk]
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    default_branch: Mapped[str] = mapped_column(String(200), default="main")
    github_repo_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    is_private: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[CreatedAt]


class ApiKey(Base):
    """A hashed, revocable, org-scoped credential for CI/CLI report uploads.

    Only the SHA-256 ``hash`` is stored; the secret is shown once at creation. ``prefix`` is a
    non-secret identifier shown in listings.
    """

    __tablename__ = "api_keys"

    id: Mapped[UuidPk]
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(32))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[CreatedAt]


class Installation(Base):
    """A GitHub App installation tied to an org."""

    __tablename__ = "installations"

    id: Mapped[UuidPk]
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"))
    github_installation_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    account_login: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[CreatedAt]


class Scan(Base):
    """One uploaded or produced ``vulnadvisor`` report for a repo at a commit/ref.

    ``commit_sha``/``ref`` are nullable: a local ``scan --upload`` outside a git checkout has no
    commit to report, and null is rendered honestly ("local scan") instead of placeholder zeros.
    """

    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_repo_created", "repo_id", "created_at"),)

    id: Mapped[UuidPk]
    repo_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    ref: Mapped[str | None] = mapped_column(String(255))
    pr_number: Mapped[int | None] = mapped_column()
    source: Mapped[str] = mapped_column(String(16), default=ScanSource.CI.value)
    tool_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default=ScanStatus.COMPLETE.value)
    degraded_sources: Mapped[list[str]] = mapped_column(JSONType, default=list)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[CreatedAt]


class Finding(Base):
    """A single scored finding; ``payload`` is the engine's JSON finding (the source of truth)."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan", "scan_id"),
        Index("ix_findings_pkg_adv", "package", "advisory_id"),
    )

    id: Mapped[UuidPk]
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    advisory_id: Mapped[str] = mapped_column(String(64))
    package: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(100))
    tier: Mapped[str] = mapped_column(String(32))
    band: Mapped[str] = mapped_column(String(16))
    priority: Mapped[float] = mapped_column(Float)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
