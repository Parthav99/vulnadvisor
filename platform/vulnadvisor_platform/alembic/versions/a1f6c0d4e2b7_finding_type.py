"""findings.finding_type column (Task 16.4 — SAST engine + output integration)

Schema-1.2 reports carry a ``finding_type`` discriminator: "dependency" (SCA) or "code" (first-
party SAST). The column is additive and defaults to "dependency" via a server_default, so every
existing row (all dependency findings) is backfilled correctly and pre-1.2 ingests keep working.

Revision ID: a1f6c0d4e2b7
Revises: f7a2d9c4e8b3
Create Date: 2026-06-13
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "a1f6c0d4e2b7"
down_revision: str | None = "f7a2d9c4e8b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "finding_type",
            sa.String(length=16),
            nullable=False,
            server_default="dependency",
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "finding_type")
