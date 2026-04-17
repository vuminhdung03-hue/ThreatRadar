"""
Data fetcher service.

Migrated from backend/collect_data.py, collect_epss.py, collect_kev.py.
Uses async httpx instead of sync requests.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ── NVD ───────────────────────────────────────────────────────────────────────

def _parse_cvss(metrics: dict) -> tuple[float | None, str | None]:
    """Extract best available CVSS score: v3.1 → v3.0 → v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("vectorString")
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        data = entries[0].get("cvssData", {})
        return data.get("baseScore"), data.get("vectorString")
    return None, None


def _parse_cpe(configurations: list[dict]) -> tuple[list[str], list[str]]:
    """
    Extract affected product CPEs and normalise to vendor:product format.
    Returns (affected_products, technologies).
    """
    affected: set[str] = set()
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    if vendor and product and vendor != "*" and product != "*":
                        affected.add(f"{vendor}:{product}")
    lst = sorted(affected)
    return lst, lst  # technologies mirrors affected_products


async def fetch_nvd_cves(
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    max_results: int = 2000,
) -> list[dict[str, Any]]:
    """
    Fetch CVEs from NVD for a date range.
    Defaults to last 7 days if no range given.
    """
    if from_date is None:
        from_date = datetime.now(timezone.utc) - timedelta(days=7)
    if to_date is None:
        to_date = datetime.now(timezone.utc)

    # NVD requires dates in ISO 8601 format without microseconds
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate": from_date.strftime(fmt),
        "pubEndDate": to_date.strftime(fmt),
        "resultsPerPage": min(max_results, 2000),
        "startIndex": 0,
    }
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    # Rate limit: 0.6s with key, 6s without
    delay = 0.6 if settings.nvd_api_key else 6.0

    cves: list[dict] = []
    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            try:
                resp = await client.get(NVD_BASE, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.error("nvd_fetch_error", error=str(e), params=params)
                break

            items = data.get("vulnerabilities", [])
            for item in items:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue

                metrics = cve_data.get("metrics", {})
                cvss_score, cvss_vector = _parse_cvss(metrics)

                descriptions = cve_data.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"), None
                )

                published_str = cve_data.get("published", "")
                try:
                    published_date = datetime.fromisoformat(
                        published_str.replace("Z", "+00:00")
                    )
                except Exception:
                    published_date = None

                configs = cve_data.get("configurations", [])
                affected_products, technologies = _parse_cpe(configs)

                cves.append(
                    {
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "description": description,
                        "published_date": published_date,
                        "affected_products": affected_products,
                        "technologies": technologies,
                    }
                )

            total = data.get("totalResults", 0)
            fetched = params["startIndex"] + len(items)
            logger.info("nvd_page_fetched", fetched=fetched, total=total)

            if fetched >= total or fetched >= max_results:
                break

            params["startIndex"] = fetched
            await asyncio.sleep(delay)

    logger.info("nvd_fetch_complete", count=len(cves))
    return cves


# ── EPSS ──────────────────────────────────────────────────────────────────────

async def fetch_epss_scores(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Returns {cve_id: (epss_score, epss_percentile)}.
    Scores are stored as 0–1 float (NOT percentage).
    """
    batch_size = 100
    results: dict[str, tuple[float, float]] = {}

    async with httpx.AsyncClient(timeout=30) as client:
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i : i + batch_size]
            params = {"cve": ",".join(batch)}
            try:
                resp = await client.get(EPSS_BASE, params=params)
                resp.raise_for_status()
                data = resp.json()
                for entry in data.get("data", []):
                    cve = entry.get("cve")
                    score = float(entry.get("epss", 0))
                    percentile = float(entry.get("percentile", 0))
                    results[cve] = (score, percentile)
            except Exception as e:
                logger.error("epss_fetch_error", batch_start=i, error=str(e))
            await asyncio.sleep(1)

    logger.info("epss_fetch_complete", count=len(results))
    return results


# ── CISA KEV ─────────────────────────────────────────────────────────────────

async def fetch_cisa_kev() -> list[str]:
    """
    Fetch CISA KEV list and return the list of CVE IDs currently in it.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            cve_ids = [
                v["cveID"]
                for v in data.get("vulnerabilities", [])
                if v.get("cveID")
            ]
            logger.info("cisa_kev_fetched", count=len(cve_ids))
            return cve_ids
        except Exception as e:
            logger.error("cisa_kev_fetch_error", error=str(e))
            return []
