"""add cpe_data JSONB column to threats

Revision ID: c4e1f2a3b5d6
Revises: b3f92c1e4a07
Create Date: 2026-04-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'c4e1f2a3b5d6'
down_revision = 'b3f92c1e4a07'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'threats',
        sa.Column(
            'cpe_data',
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.create_index(
        'idx_threats_cpe_data',
        'threats',
        ['cpe_data'],
        postgresql_using='gin',
    )


def downgrade() -> None:
    op.drop_index('idx_threats_cpe_data', table_name='threats')
    op.drop_column('threats', 'cpe_data')
