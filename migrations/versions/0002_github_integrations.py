"""github integrations

Add the github_integrations table — a connected repo RedHive can open
remediation pull requests against. Access token stored encrypted.

Revision ID: 0002_github
Revises: 0001_initial
Create Date: 2026-06-09
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_github"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "github_integrations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("repo_full_name", sa.String(255), nullable=False),
        sa.Column("token_encrypted", sa.Text(), nullable=False),
        sa.Column("default_branch", sa.String(120), nullable=False, server_default="main"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("org_id", "repo_full_name", name="uq_github_org_repo"),
    )
    op.create_index("ix_github_integrations_org_id", "github_integrations", ["org_id"])


def downgrade() -> None:
    op.drop_table("github_integrations")
