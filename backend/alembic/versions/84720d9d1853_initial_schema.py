"""initial_schema

Revision ID: 84720d9d1853
Revises:
Create Date: 2026-04-14

This migration creates the full ThreatRadar schema from scratch.
For an existing database, stamp with: alembic stamp 84720d9d1853
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

revision: str = "84720d9d1853"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threats",
        sa.Column("cve_id", sa.String(20), primary_key=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cvss_vector", sa.String(100), nullable=True),
        sa.Column("epss_score", sa.Float, nullable=True),
        sa.Column("epss_percentile", sa.Float, nullable=True),
        sa.Column("in_cisa_kev", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("in_vulncheck_kev", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("published_date", sa.DateTime, nullable=True),
        sa.Column("affected_products", ARRAY(sa.Text), nullable=True),
        sa.Column("technologies", ARRAY(sa.Text), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=True),
        if_not_exists=True,
    )
    op.create_index("idx_threats_published", "threats",
                    [sa.literal_column("published_date DESC")], if_not_exists=True)
    op.create_index("idx_threats_cvss", "threats",
                    [sa.literal_column("cvss_score DESC")], if_not_exists=True)
    op.create_index("idx_threats_kev", "threats", ["in_cisa_kev"], if_not_exists=True)
    op.create_index("idx_threats_technologies", "threats", ["technologies"],
                    postgresql_using="gin", if_not_exists=True)

    op.create_table(
        "environment_profiles",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("technologies", ARRAY(sa.Text), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=True),
        if_not_exists=True,
    )
    op.create_index("idx_env_technologies", "environment_profiles", ["technologies"],
                    postgresql_using="gin", if_not_exists=True)

    op.create_table(
        "threat_scores",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("threat_id", sa.String(20),
                  sa.ForeignKey("threats.cve_id", ondelete="CASCADE"), nullable=True),
        sa.Column("environment_id", sa.Integer,
                  sa.ForeignKey("environment_profiles.id", ondelete="CASCADE"), nullable=True),
        sa.Column("composite_score", sa.Float,
                  sa.CheckConstraint("composite_score >= 0 AND composite_score <= 1"),
                  nullable=True),
        sa.Column("priority_level", sa.String(10), nullable=True),
        sa.Column("tech_match_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("score_breakdown", JSONB, nullable=True),
        sa.Column("calculated_at", sa.DateTime, server_default=sa.text("NOW()"), nullable=True),
        sa.UniqueConstraint("threat_id", "environment_id"),
        if_not_exists=True,
    )
    op.create_index("idx_scores_composite", "threat_scores",
                    ["environment_id", sa.literal_column("composite_score DESC")],
                    if_not_exists=True)


def downgrade() -> None:
    op.drop_index("idx_scores_composite", table_name="threat_scores")
    op.drop_table("threat_scores")
    op.drop_index("idx_env_technologies", table_name="environment_profiles")
    op.drop_table("environment_profiles")
    op.drop_index("idx_threats_technologies", table_name="threats")
    op.drop_index("idx_threats_kev", table_name="threats")
    op.drop_index("idx_threats_cvss", table_name="threats")
    op.drop_index("idx_threats_published", table_name="threats")
    op.drop_table("threats")
