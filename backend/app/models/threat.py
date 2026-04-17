from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Threat(Base):
    __tablename__ = "threats"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(100))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    in_cisa_kev: Mapped[bool] = mapped_column(Boolean, server_default="false")
    in_vulncheck_kev: Mapped[bool] = mapped_column(Boolean, server_default="false")
    description: Mapped[str | None] = mapped_column(Text)
    published_date: Mapped[datetime | None] = mapped_column(DateTime)
    affected_products: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    technologies: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    cpe_data: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, server_default=func.now())
