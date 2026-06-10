"""scan llm usage

Add per-scan LLM token + cost columns so the dashboard can show what each
engagement cost to run.

Revision ID: 0003_usage
Revises: 0002_github
Create Date: 2026-06-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_usage"
down_revision = "0002_github"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("tokens_used", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("llm_calls", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("cost_usd", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "cost_usd")
    op.drop_column("scans", "llm_calls")
    op.drop_column("scans", "tokens_used")
