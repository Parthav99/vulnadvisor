"""scans.suggestions column (Task 17.2 — PR review agent: validated in-line fixes)

CI runs ``vulnadvisor fix --suggest-json`` and uploads the validated patches alongside the report;
they are stored on the scan so the GitHub App can post them as one-click in-line PR ``suggestion``
comments. The column is additive and defaults to an empty list via a server_default, so every
existing scan row reads back as "no suggestions" and ordinary uploads keep working unchanged.

Revision ID: c3b9e7d1f4a8
Revises: a1f6c0d4e2b7
Create Date: 2026-06-14
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c3b9e7d1f4a8"
down_revision: str | None = "a1f6c0d4e2b7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "suggestions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
            server_default="[]",
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "suggestions")
