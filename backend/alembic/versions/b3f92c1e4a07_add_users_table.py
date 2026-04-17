"""add_users_table

Revision ID: b3f92c1e4a07
Revises: 84720d9d1853
Create Date: 2026-04-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b3f92c1e4a07"
down_revision: Union[str, Sequence[str], None] = "84720d9d1853"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="analyst"),
        sa.Column(
            "environment_id",
            sa.Integer,
            sa.ForeignKey("environment_profiles.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=False),
        if_not_exists=True,
    )
    op.create_index("idx_users_email", "users", ["email"], unique=True, if_not_exists=True)


def downgrade() -> None:
    op.drop_index("idx_users_email", table_name="users")
    op.drop_table("users")
