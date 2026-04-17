"""
Celery tasks for scheduled data synchronisation.

These tasks wrap the async service functions using asyncio.run(),
which is safe inside Celery workers (each task runs in its own thread/process).
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select, text

from app.tasks.celery_app import celery_app

logger = structlog.get_logger()


def _run(coro):
    """Run an async coroutine from a synchronous Celery task."""
    return asyncio.run(coro)


# ── NVD CVE sync ─────────────────────────────────────────────────────────────

@celery_app.task(name="app.tasks.data_sync.sync_nvd_cves", bind=True, max_retries=3)
def sync_nvd_cves(self, days_back: int = 7):
    """Fetch CVEs published in the last N days from NVD and upsert into DB."""
    async def _run_sync():
        from app.database import async_session_factory
        from app.services.data_fetcher import fetch_nvd_cves

        to_date = datetime.now(timezone.utc)
        from_date = to_date - timedelta(days=days_back)

        logger.info("task_nvd_sync_start", from_date=str(from_date), to_date=str(to_date))
        cves = await fetch_nvd_cves(from_date=from_date, to_date=to_date)

        inserted = updated = 0
        async with async_session_factory() as db:
            for cve in cves:
                result = await db.execute(
                    text("""
                        INSERT INTO threats
                            (cve_id, cvss_score, cvss_vector, description,
                             published_date, affected_products, technologies)
                        VALUES
                            (:cve_id, :cvss_score, :cvss_vector, :description,
                             :published_date, :affected_products, :technologies)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            cvss_score        = EXCLUDED.cvss_score,
                            cvss_vector       = EXCLUDED.cvss_vector,
                            description       = EXCLUDED.description,
                            affected_products = EXCLUDED.affected_products,
                            technologies      = EXCLUDED.technologies
                        RETURNING (xmax = 0) AS inserted
                    """),
                    {
                        "cve_id": cve["cve_id"],
                        "cvss_score": cve.get("cvss_score"),
                        "cvss_vector": cve.get("cvss_vector"),
                        "description": cve.get("description"),
                        "published_date": cve.get("published_date"),
                        "affected_products": cve.get("affected_products") or [],
                        "technologies": cve.get("technologies") or [],
                    },
                )
                row = result.fetchone()
                if row and row[0]:
                    inserted += 1
                else:
                    updated += 1
            await db.commit()

        logger.info("task_nvd_sync_complete", inserted=inserted, updated=updated)
        return {"inserted": inserted, "updated": updated}

    try:
        return _run(_run_sync())
    except Exception as exc:
        logger.error("task_nvd_sync_failed", error=str(exc))
        raise self.retry(exc=exc, countdown=60)


# ── EPSS sync ─────────────────────────────────────────────────────────────────

@celery_app.task(name="app.tasks.data_sync.sync_epss_scores", bind=True, max_retries=3)
def sync_epss_scores(self):
    """Fetch EPSS scores for all CVEs in the DB and update."""
    async def _run_sync():
        from app.database import async_session_factory
        from app.services.data_fetcher import fetch_epss_scores

        async with async_session_factory() as db:
            result = await db.execute(text("SELECT cve_id FROM threats"))
            cve_ids = [row[0] for row in result]

        logger.info("task_epss_sync_start", cve_count=len(cve_ids))
        scores = await fetch_epss_scores(cve_ids)

        async with async_session_factory() as db:
            params = [
                {"cve_id": cve_id, "epss": epss, "percentile": pct}
                for cve_id, (epss, pct) in scores.items()
            ]
            if params:
                await db.execute(
                    text("""
                        UPDATE threats
                        SET epss_score = :epss, epss_percentile = :percentile
                        WHERE cve_id = :cve_id
                    """),
                    params,
                )
                await db.commit()

        logger.info("task_epss_sync_complete", updated=len(scores))
        return {"updated": len(scores)}

    try:
        return _run(_run_sync())
    except Exception as exc:
        logger.error("task_epss_sync_failed", error=str(exc))
        raise self.retry(exc=exc, countdown=120)


# ── KEV sync ──────────────────────────────────────────────────────────────────

@celery_app.task(name="app.tasks.data_sync.sync_kev_lists", bind=True, max_retries=3)
def sync_kev_lists(self):
    """Sync CISA KEV flags — reset all, then mark current list."""
    async def _run_sync():
        from app.database import async_session_factory
        from app.services.data_fetcher import fetch_cisa_kev

        kev_ids = await fetch_cisa_kev()
        logger.info("task_kev_sync_start", kev_count=len(kev_ids))

        async with async_session_factory() as db:
            # Reset all flags first, then mark current KEV entries
            await db.execute(text("UPDATE threats SET in_cisa_kev = FALSE"))
            if kev_ids:
                await db.execute(
                    text("UPDATE threats SET in_cisa_kev = TRUE WHERE cve_id = ANY(:ids)"),
                    {"ids": kev_ids},
                )
            await db.commit()

        logger.info("task_kev_sync_complete", flagged=len(kev_ids))
        return {"flagged": len(kev_ids)}

    try:
        return _run(_run_sync())
    except Exception as exc:
        logger.error("task_kev_sync_failed", error=str(exc))
        raise self.retry(exc=exc, countdown=60)


# ── Score recalculation ───────────────────────────────────────────────────────

@celery_app.task(name="app.tasks.data_sync.recalculate_scores", bind=True, max_retries=2)
def recalculate_scores(self, environment_id: int | None = None):
    """
    Recompute composite scores.
    If environment_id is given, only recalculates for that environment.
    Otherwise recalculates for all environments.
    """
    async def _run_sync():
        from app.database import async_session_factory
        from app.services.scoring import (
            recalculate_all_scores,
            recalculate_scores_for_environment,
        )

        async with async_session_factory() as db:
            if environment_id is not None:
                count = await recalculate_scores_for_environment(db, environment_id)
                return {"environment_id": environment_id, "upserted": count}
            else:
                totals = await recalculate_all_scores(db)
                return {"totals": totals}

    try:
        return _run(_run_sync())
    except Exception as exc:
        logger.error("task_score_recalc_failed", error=str(exc))
        raise self.retry(exc=exc, countdown=60)
