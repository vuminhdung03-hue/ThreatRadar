from datetime import datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, and_, cast, func, or_, select, case
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.score import ThreatScore
from app.models.threat import Threat
from app.models.user import User
from app.schemas.threat import ThreatDetailWithScore, ThreatListResponse, ThreatWithScore
from app.services.auth import get_current_user

logger = structlog.get_logger()
router = APIRouter(tags=["threats"])


def _build_threat_filters(
    stmt,
    min_cvss: float | None,
    min_epss: float | None,
    kev_only: bool,
    from_date: datetime | None,
    to_date: datetime | None,
    technologies: list[str] | None,
):
    """Apply common WHERE conditions to a threat query."""
    if min_cvss is not None:
        stmt = stmt.where(Threat.cvss_score >= min_cvss)
    if min_epss is not None:
        stmt = stmt.where(Threat.epss_score >= min_epss)
    if kev_only:
        stmt = stmt.where(
            or_(Threat.in_cisa_kev == True, Threat.in_vulncheck_kev == True)  # noqa: E712
        )
    if from_date:
        stmt = stmt.where(Threat.published_date >= from_date)
    if to_date:
        stmt = stmt.where(Threat.published_date <= to_date)
    if technologies:
        # PostgreSQL && (overlap) operator: any threat technology matches any filter technology
        stmt = stmt.where(
            Threat.technologies.op("&&")(cast(technologies, ARRAY(String)))
        )
    return stmt


@router.get("/threats", response_model=ThreatListResponse)
async def list_threats(
    environment_id: int | None = Query(None, description="Filter and rank by environment"),
    min_score: float | None = Query(None, ge=0, le=1),
    min_cvss: float | None = Query(None, ge=0, le=10),
    min_epss: float | None = Query(None, ge=0, le=1),
    kev_only: bool = Query(False),
    technologies: list[str] | None = Query(None),
    from_date: datetime | None = Query(None),
    to_date: datetime | None = Query(None),
    priority_level: str | None = Query(None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$"),
    sort_by: str = Query("cvss", pattern="^(cvss|epss|date|score)$"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Analysts are locked to their assigned environment
    if current_user.role == "analyst" and current_user.environment_id is not None:
        environment_id = current_user.environment_id
    if environment_id:
        # Join with threat_scores for scoring data
        data_stmt = (
            select(Threat, ThreatScore)
            .outerjoin(
                ThreatScore,
                and_(
                    ThreatScore.threat_id == Threat.cve_id,
                    ThreatScore.environment_id == environment_id,
                ),
            )
        )
        data_stmt = _build_threat_filters(
            data_stmt, min_cvss, min_epss, kev_only, from_date, to_date, technologies
        )
        if min_score is not None:
            data_stmt = data_stmt.where(ThreatScore.composite_score >= min_score)
        if priority_level is not None:
            data_stmt = data_stmt.where(ThreatScore.priority_level == priority_level)

        # Count (separate, lightweight query)
        count_stmt = select(func.count(Threat.cve_id)).outerjoin(
            ThreatScore,
            and_(
                ThreatScore.threat_id == Threat.cve_id,
                ThreatScore.environment_id == environment_id,
            ),
        )
        count_stmt = _build_threat_filters(
            count_stmt, min_cvss, min_epss, kev_only, from_date, to_date, technologies
        )
        if min_score is not None:
            count_stmt = count_stmt.where(ThreatScore.composite_score >= min_score)
        if priority_level is not None:
            count_stmt = count_stmt.where(ThreatScore.priority_level == priority_level)

        # Sort
        if sort_by == "score":
            data_stmt = data_stmt.order_by(ThreatScore.composite_score.desc().nullslast())
        elif sort_by == "epss":
            data_stmt = data_stmt.order_by(Threat.epss_score.desc().nullslast())
        elif sort_by == "date":
            data_stmt = data_stmt.order_by(Threat.published_date.desc().nullslast())
        else:
            data_stmt = data_stmt.order_by(Threat.cvss_score.desc().nullslast())

        data_stmt = data_stmt.limit(limit).offset((page - 1) * limit)

        total = await db.scalar(count_stmt) or 0
        rows = (await db.execute(data_stmt)).all()

        items: list[ThreatWithScore] = []
        for threat, score in rows:
            item = ThreatWithScore.model_validate(threat)
            if score:
                item.composite_score = score.composite_score
                item.priority_level = score.priority_level
                item.tech_match_count = score.tech_match_count or 0
                item.score_breakdown = score.score_breakdown
            items.append(item)

    else:
        # No environment — plain threat list
        data_stmt = select(Threat)
        data_stmt = _build_threat_filters(
            data_stmt, min_cvss, min_epss, kev_only, from_date, to_date, technologies
        )

        count_stmt = select(func.count(Threat.cve_id))
        count_stmt = _build_threat_filters(
            count_stmt, min_cvss, min_epss, kev_only, from_date, to_date, technologies
        )

        if priority_level is not None:
            # Derive priority from CVSS (same thresholds as dashboard stats)
            cvss_priority = case(
                (Threat.cvss_score >= 9.0, "CRITICAL"),
                (Threat.cvss_score >= 7.0, "HIGH"),
                (Threat.cvss_score >= 4.0, "MEDIUM"),
                else_="LOW",
            )
            data_stmt = data_stmt.where(cvss_priority == priority_level)
            count_stmt = count_stmt.where(cvss_priority == priority_level)

        if sort_by == "epss":
            data_stmt = data_stmt.order_by(Threat.epss_score.desc().nullslast())
        elif sort_by == "date":
            data_stmt = data_stmt.order_by(Threat.published_date.desc().nullslast())
        else:
            data_stmt = data_stmt.order_by(Threat.cvss_score.desc().nullslast())

        data_stmt = data_stmt.limit(limit).offset((page - 1) * limit)

        total = await db.scalar(count_stmt) or 0
        threats = (await db.execute(data_stmt)).scalars().all()
        items = [ThreatWithScore.model_validate(t) for t in threats]

    return ThreatListResponse(total=total, page=page, limit=limit, items=items)


@router.get("/threats/{cve_id}", response_model=ThreatDetailWithScore)
async def get_threat(
    cve_id: str,
    environment_id: int | None = Query(None, description="Include score for this environment"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role == "analyst" and current_user.environment_id is not None:
        environment_id = current_user.environment_id
    threat = await db.get(Threat, cve_id)
    if not threat:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    result = ThreatDetailWithScore.model_validate(threat)

    if environment_id:
        score = await db.scalar(
            select(ThreatScore).where(
                ThreatScore.threat_id == cve_id,
                ThreatScore.environment_id == environment_id,
            )
        )
        if score:
            result.composite_score = score.composite_score
            result.priority_level = score.priority_level
            result.tech_match_count = score.tech_match_count or 0
            result.score_breakdown = score.score_breakdown

    return result
