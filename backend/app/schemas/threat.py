from datetime import datetime

from pydantic import BaseModel


class _ScoreFields(BaseModel):
    """Mixin: environment-specific score data appended to threat responses."""

    composite_score: float | None = None
    priority_level: str | None = None
    tech_match_count: int = 0
    score_breakdown: dict | None = None


class ThreatResponse(BaseModel):
    """Compact threat representation used in list responses."""

    model_config = {"from_attributes": True}

    cve_id: str
    cvss_score: float | None
    epss_score: float | None
    epss_percentile: float | None
    in_cisa_kev: bool
    in_vulncheck_kev: bool
    description: str | None
    published_date: datetime | None
    technologies: list[str] | None


class ThreatDetail(ThreatResponse):
    """Full threat detail including products and vector."""

    cvss_vector: str | None
    affected_products: list[str] | None
    created_at: datetime | None


class ThreatWithScore(ThreatResponse, _ScoreFields):
    """Threat enriched with environment-specific score data."""


class ThreatDetailWithScore(ThreatDetail, _ScoreFields):
    """Full detail + score breakdown for the single-threat endpoint."""


class ThreatListResponse(BaseModel):
    """Paginated list of threats."""

    total: int
    page: int
    limit: int
    items: list[ThreatWithScore]
