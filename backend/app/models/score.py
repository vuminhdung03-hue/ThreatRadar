from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ThreatScore(Base):
    __tablename__ = "threat_scores"
    __table_args__ = (
        UniqueConstraint("threat_id", "environment_id"),
        CheckConstraint("composite_score >= 0 AND composite_score <= 1"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    threat_id: Mapped[str | None] = mapped_column(
        String(20), ForeignKey("threats.cve_id", ondelete="CASCADE")
    )
    environment_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("environment_profiles.id", ondelete="CASCADE")
    )
    composite_score: Mapped[float | None] = mapped_column(Float)
    priority_level: Mapped[str | None] = mapped_column(String(10))
    tech_match_count: Mapped[int] = mapped_column(Integer, server_default="0")
    score_breakdown: Mapped[dict | None] = mapped_column(JSONB)
    calculated_at: Mapped[datetime | None] = mapped_column(DateTime, server_default=func.now())
