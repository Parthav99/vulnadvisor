"""copilot BYO key columns + usage table (Task 15.1 — triage copilot backend)

Adds the encrypted org-level Anthropic key (Fernet ciphertext + non-secret hint) on orgs, and
the per-(org, UTC day) usage counter that backs the copilot's daily request cap.

Revision ID: f7a2d9c4e8b3
Revises: d4c8b6e2f1a9
Create Date: 2026-06-12
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "f7a2d9c4e8b3"
down_revision: str | None = "d4c8b6e2f1a9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "orgs", sa.Column("copilot_key_ciphertext", sa.String(length=1024), nullable=True)
    )
    op.add_column("orgs", sa.Column("copilot_key_hint", sa.String(length=16), nullable=True))
    op.create_table(
        "copilot_usage",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("day", sa.String(length=10), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "day", name="uq_copilot_usage_org_day"),
    )


def downgrade() -> None:
    op.drop_table("copilot_usage")
    op.drop_column("orgs", "copilot_key_hint")
    op.drop_column("orgs", "copilot_key_ciphertext")
