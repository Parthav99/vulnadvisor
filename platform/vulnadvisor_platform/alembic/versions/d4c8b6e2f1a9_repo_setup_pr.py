"""repositories setup-PR columns (Task 14.2 — one-click GitHub App install + auto-setup PR)

Tracks the onboarding setup PR per repository: its number/url and last known lifecycle state
("open" / "merged" / null), kept current by the pull_request webhook so the dashboard can show
honest Not set up / PR open / Merged / Receiving scans chips.

Revision ID: d4c8b6e2f1a9
Revises: b9e4d3a1c7f2
Create Date: 2026-06-12
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "d4c8b6e2f1a9"
down_revision: str | None = "b9e4d3a1c7f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("repositories", sa.Column("setup_pr_number", sa.Integer(), nullable=True))
    op.add_column("repositories", sa.Column("setup_pr_url", sa.String(length=500), nullable=True))
    op.add_column("repositories", sa.Column("setup_pr_state", sa.String(length=16), nullable=True))


def downgrade() -> None:
    op.drop_column("repositories", "setup_pr_state")
    op.drop_column("repositories", "setup_pr_url")
    op.drop_column("repositories", "setup_pr_number")
