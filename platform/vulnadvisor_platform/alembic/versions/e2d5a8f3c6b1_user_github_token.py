"""users.github_token columns (Task 17.4 Part 3 — zero-App setup PR via OAuth token)

Persists the logged-in user's GitHub OAuth access token, encrypted at rest with the same Fernet
helper as the copilot BYO key (key derived from SECRET_KEY), plus the space-joined granted scopes in
clear so the setup-PR path can tell whether the token is write-capable (repo/workflow) without
decrypting. Both columns are additive and nullable, so every existing user row reads back as "no
token persisted" and ordinary logins keep working unchanged.

Revision ID: e2d5a8f3c6b1
Revises: c3b9e7d1f4a8
Create Date: 2026-06-14
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "e2d5a8f3c6b1"
down_revision: str | None = "c3b9e7d1f4a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users", sa.Column("github_token_ciphertext", sa.String(length=1024), nullable=True)
    )
    op.add_column("users", sa.Column("github_token_scopes", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "github_token_scopes")
    op.drop_column("users", "github_token_ciphertext")
