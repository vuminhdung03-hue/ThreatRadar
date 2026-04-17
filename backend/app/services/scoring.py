"""
Threat scoring service.

Migrated from backend/calculate_scores.py with two fixes:
  1. EPSS is stored as 0–1 float; old script divided by 100 (bug) — corrected here.
  2. Column is `calculated_at`, not `computed_at`.
"""

import json
from datetime import datetime

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.environment import EnvironmentProfile
from app.models.threat import Threat
from app.services.cpe_matcher import CPEMatcher

logger = structlog.get_logger()


def _priority_from_score(score: float) -> str:
    if score >= 0.75:
        return "CRITICAL"
    if score >= 0.50:
        return "HIGH"
    if score >= 0.25:
        return "MEDIUM"
    return "LOW"


def calculate_composite_score(
    cvss: float | None,
    epss: float | None,
    is_kev: bool,
    published_date: datetime | None,
    tech_match_count: int,
    tech_match_score: float = 0.0,
) -> tuple[float, str, dict]:
    """
    Returns (composite_score, priority_level, breakdown_dict).

    Weights: CVSS 40% | EPSS 30% | Tech 20% | Recency 10%
    KEV multiplier: 1.5×

    tech_match_score is the continuous score from CPEMatcher (0–N, capped at 1).
    tech_match_count is the integer count stored in DB for reference.
    """
    cvss_contribution = ((cvss or 0) / 10.0) * 0.4
    epss_contribution = (epss or 0) * 0.3  # EPSS stored as 0–1, no /100 needed

    recency_score = 0.0
    if published_date:
        tz = published_date.tzinfo
        days_old = (datetime.now(tz) - published_date).days
        recency_score = max(0.0, 1.0 - (days_old / 90))
    recency_contribution = recency_score * 0.1

    tech_contribution = min(tech_match_score, 1.0) * 0.2

    base_score = cvss_contribution + epss_contribution + tech_contribution + recency_contribution
    multiplier = 1.5 if is_kev else 1.0
    final_score = min(base_score * multiplier, 1.0)

    breakdown = {
        "cvss_contribution": round(cvss_contribution, 4),
        "epss_contribution": round(epss_contribution, 4),
        "tech_contribution": round(tech_contribution, 4),
        "recency_contribution": round(recency_contribution, 4),
        "kev_multiplier": multiplier,
        "base_score": round(base_score, 4),
        "final_score": round(final_score, 4),
        "tech_match_count": tech_match_count,
        "tech_match_score": round(tech_match_score, 4),
    }
    return final_score, _priority_from_score(final_score), breakdown


_UPSERT_SQL = text("""
    INSERT INTO threat_scores
        (threat_id, environment_id, composite_score, priority_level,
         tech_match_count, score_breakdown, calculated_at)
    VALUES
        (:threat_id, :env_id, :score, :priority,
         :matches, :breakdown::jsonb, NOW())
    ON CONFLICT (threat_id, environment_id) DO UPDATE SET
        composite_score  = EXCLUDED.composite_score,
        priority_level   = EXCLUDED.priority_level,
        tech_match_count = EXCLUDED.tech_match_count,
        score_breakdown  = EXCLUDED.score_breakdown,
        calculated_at    = NOW()
""")


async def recalculate_scores_for_environment(
    db: AsyncSession, environment_id: int
) -> int:
    """
    (Re)calculate composite scores for all threats in a single environment.
    Batches all upserts into one executemany call. Returns count of rows upserted.
    """
    env = await db.get(EnvironmentProfile, environment_id)
    if not env:
        logger.warning("scoring_env_not_found", environment_id=environment_id)
        return 0

    env_tech_set = set(env.technologies or [])
    logger.info("scoring_start", env=env.name, tech_count=len(env_tech_set))

    result = await db.execute(
        select(
            Threat.cve_id,
            Threat.cvss_score,
            Threat.epss_score,
            (Threat.in_cisa_kev | Threat.in_vulncheck_kev).label("is_kev"),
            Threat.published_date,
            Threat.technologies,
            Threat.cpe_data,
        )
    )
    threats = result.all()

    env_techs = list(env_tech_set)
    params_list = []
    for cve_id, cvss, epss, is_kev, pub_date, techs, cpe_data in threats:
        if cpe_data:
            matches, match_score = CPEMatcher.count_matches(env_techs, cpe_data)
        else:
            # Fallback: build synthetic CPE entries from technologies TEXT[]
            synthetic = [
                {"vendor": p.split(":")[0], "product": p.split(":")[1]}
                for p in (techs or [])
                if ":" in p
            ]
            matches, match_score = CPEMatcher.count_matches(env_techs, synthetic)

        score, priority, breakdown = calculate_composite_score(
            cvss, epss, bool(is_kev), pub_date, matches, match_score
        )
        params_list.append({
            "threat_id": cve_id,
            "env_id": environment_id,
            "score": score,
            "priority": priority,
            "matches": matches,
            "breakdown": json.dumps(breakdown),
        })

    await db.execute(_UPSERT_SQL, params_list)
    await db.commit()
    logger.info("scoring_complete", env=env.name, upserted=len(params_list))
    return len(params_list)


async def recalculate_all_scores(db: AsyncSession) -> dict[int, int]:
    """Recalculate scores for every environment. Returns {env_id: count}."""
    result = await db.execute(select(EnvironmentProfile.id))
    env_ids = [row[0] for row in result]
    totals: dict[int, int] = {}
    for env_id in env_ids:
        totals[env_id] = await recalculate_scores_for_environment(db, env_id)
    return totals
