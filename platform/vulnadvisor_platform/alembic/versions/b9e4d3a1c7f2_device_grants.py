"""device_grants table (Task 14.1 — ``vulnadvisor login`` device flow)

Stores device-flow login grants: a short user code (approved in the dashboard) plus the SHA-256
hash of the high-entropy device code the CLI polls with. The minted API key's plaintext is never
stored — only the ``api_key_id`` binding the grant to the key it produced.

Revision ID: b9e4d3a1c7f2
Revises: 7c41aa90d2e1
Create Date: 2026-06-12
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b9e4d3a1c7f2"
down_revision: str | None = "7c41aa90d2e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "device_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_code", sa.String(length=16), nullable=False),
        sa.Column("device_code_hash", sa.String(length=64), nullable=False),
        sa.Column("client_name", sa.String(length=200), nullable=True),
        sa.Column("requester_ip", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("api_key_id", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["api_key_id"], ["api_keys.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_code"),
        sa.UniqueConstraint("device_code_hash"),
    )
    op.create_index("ix_device_grants_ip_created", "device_grants", ["requester_ip", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_device_grants_ip_created", table_name="device_grants")
    op.drop_table("device_grants")
