from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.score import ThreatScore
from app.models.threat import Threat
from app.models.user import User
from app.services.auth import get_current_user

logger = structlog.get_logger()
router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
async def dashboard_stats(
    environment_id: int | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role == "analyst" and current_user.environment_id is not None:
        environment_id = current_user.environment_id
    """
    Aggregate counts and priority distribution.
    If environment_id is provided, uses composite scores for priority bucketing.
    """
    # Single query for totals + averages
    totals_result = await db.execute(
        select(
            func.count(Threat.cve_id).label("total"),
            func.count(Threat.cve_id).filter(
                or_(Threat.in_cisa_kev == True, Threat.in_vulncheck_kev == True)  # noqa: E712
            ).label("kev_count"),
            func.avg(Threat.cvss_score).label("avg_cvss"),
            func.avg(Threat.epss_score).label("avg_epss"),
        )
    )
    row = totals_result.one()
    total = row.total or 0
    kev_count = row.kev_count or 0
    avg_cvss = round(row.avg_cvss or 0, 2)
    avg_epss = round(row.avg_epss or 0, 4)

    # Priority distribution
    if environment_id:
        priority_result = await db.execute(
            select(
                ThreatScore.priority_level,
                func.count(ThreatScore.id).label("count"),
            )
            .where(ThreatScore.environment_id == environment_id)
            .where(ThreatScore.priority_level.isnot(None))
            .group_by(ThreatScore.priority_level)
        )
        by_priority = {r.priority_level: r.count for r in priority_result}
        unscored = total - sum(by_priority.values())
        if unscored > 0:
            by_priority["UNSCORED"] = unscored
    else:
        # Bucket by CVSS when no environment selected
        priority_result = await db.execute(
            select(
                case(
                    (Threat.cvss_score >= 9.0, "CRITICAL"),
                    (Threat.cvss_score >= 7.0, "HIGH"),
                    (Threat.cvss_score >= 4.0, "MEDIUM"),
                    else_="LOW",
                ).label("priority"),
                func.count(Threat.cve_id).label("count"),
            ).group_by("priority")
        )
        by_priority = {r.priority: r.count for r in priority_result}

    return {
        "total_threats": total,
        "kev_count": kev_count,
        "avg_cvss": avg_cvss,
        "avg_epss": avg_epss,
        "by_priority": by_priority,
        "environment_id": environment_id,
    }


@router.get("/trends")
async def dashboard_trends(
    months: int = Query(12, ge=1, le=36),
    db: AsyncSession = Depends(get_db),
):
    """CVEs published per month for the last N months."""
    cutoff = datetime.utcnow() - timedelta(days=months * 30)

    result = await db.execute(
        select(
            func.date_trunc("month", Threat.published_date).label("month"),
            func.count(Threat.cve_id).label("count"),
        )
        .where(Threat.published_date >= cutoff)
        .group_by("month")
        .order_by("month")
    )

    return {
        "months": months,
        "data": [
            {"month": r.month.strftime("%Y-%m") if r.month else None, "count": r.count}
            for r in result
        ],
    }
