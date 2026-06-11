"""scans.commit_sha / scans.ref nullable (Task 12.2 — scan metadata honesty)

A local ``scan --upload`` outside a git checkout has no commit/ref to report; null is stored and
rendered as "local scan" instead of placeholder zeros.

Revision ID: 7c41aa90d2e1
Revises: 593b20e58b31
Create Date: 2026-06-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "7c41aa90d2e1"
down_revision: str | None = "593b20e58b31"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("scans", "commit_sha", existing_type=sa.String(length=40), nullable=True)
    op.alter_column("scans", "ref", existing_type=sa.String(length=255), nullable=True)


def downgrade() -> None:
    # Nulls must be backfilled before the columns can be NOT NULL again; the placeholder values
    # match what pre-12.2 clients sent.
    op.execute(
        "UPDATE scans SET commit_sha = '0000000000000000000000000000000000000000' WHERE commit_sha IS NULL"
    )
    op.execute("UPDATE scans SET ref = 'refs/heads/main' WHERE ref IS NULL")
    op.alter_column("scans", "commit_sha", existing_type=sa.String(length=40), nullable=False)
    op.alter_column("scans", "ref", existing_type=sa.String(length=255), nullable=False)
