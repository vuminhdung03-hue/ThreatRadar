"""
EPSS Score Collector
Fetches exploit-probability scores from FIRST.org for CVEs in the database.

Usage:
  python collect_epss.py               # update all CVEs
  python collect_epss.py --missing-only # only CVEs where epss_score IS NULL
"""

import argparse
import os
import time

import psycopg2
import requests
from dotenv import load_dotenv

load_dotenv()

EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100     # CVE IDs per API request (well within URL-length limits)
SLEEP_BETWEEN = 1.0  # seconds between batches


def _psycopg2_url(raw_url: str) -> str:
    return raw_url.replace('postgresql+asyncpg://', 'postgresql://', 1)


def fetch_epss_batch(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """
    Fetch EPSS scores for up to 100 CVE IDs in a single API call.
    Returns {cve_id: (epss_score, epss_percentile)}.
    """
    try:
        params = {"cve": ",".join(cve_ids), "limit": len(cve_ids)}
        resp = requests.get(EPSS_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        results: dict[str, tuple[float, float]] = {}
        for entry in data.get("data", []):
            cve = entry.get("cve", "")
            if cve:
                results[cve] = (
                    float(entry.get("epss", 0)),
                    float(entry.get("percentile", 0)),
                )
        return results

    except Exception as e:
        print(f"  ✗ Batch fetch error: {e}")
        return {}


def get_cve_ids(conn, missing_only: bool) -> list[str]:
    cur = conn.cursor()
    if missing_only:
        cur.execute("SELECT cve_id FROM threats WHERE epss_score IS NULL ORDER BY cve_id")
    else:
        cur.execute("SELECT cve_id FROM threats ORDER BY cve_id")
    ids = [row[0] for row in cur.fetchall()]
    cur.close()
    return ids


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect EPSS scores from FIRST.org")
    parser.add_argument(
        "--missing-only",
        action="store_true",
        help="Only fetch CVEs where epss_score IS NULL",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ThreatRadar — EPSS Data Collection")
    print("=" * 60)

    db_url = _psycopg2_url(os.getenv("DATABASE_URL", ""))
    try:
        conn = psycopg2.connect(db_url)
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM threats WHERE epss_score IS NULL")
    null_before = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM threats")
    total_threats = cur.fetchone()[0]
    cur.close()

    print(f"Threats total          : {total_threats}")
    print(f"EPSS NULL before       : {null_before}")

    cve_ids = get_cve_ids(conn, args.missing_only)
    mode = "missing-only" if args.missing_only else "all"
    print(f"CVEs to fetch ({mode}) : {len(cve_ids)}")

    if not cve_ids:
        print("Nothing to do.")
        conn.close()
        return

    print(f"\nBatch size: {BATCH_SIZE} CVEs/request, {SLEEP_BETWEEN}s between batches")
    print("Fetching from FIRST.org API...\n")

    updated = not_found = errors = 0
    batches = [cve_ids[i:i + BATCH_SIZE] for i in range(0, len(cve_ids), BATCH_SIZE)]
    cur = conn.cursor()

    for batch_num, batch in enumerate(batches, 1):
        scores = fetch_epss_batch(batch)

        for cve_id in batch:
            if cve_id in scores:
                epss, percentile = scores[cve_id]
                try:
                    cur.execute(
                        "UPDATE threats SET epss_score = %s, epss_percentile = %s WHERE cve_id = %s",
                        (epss, percentile, cve_id),
                    )
                    updated += 1
                except Exception as e:
                    print(f"  ✗ DB error for {cve_id}: {e}")
                    conn.rollback()
                    errors += 1
            else:
                not_found += 1

        # Commit every 10 batches (1000 CVEs)
        if batch_num % 10 == 0:
            conn.commit()
            pct = batch_num / len(batches) * 100
            print(
                f"  Batch {batch_num}/{len(batches)} ({pct:.0f}%)  "
                f"+{updated} updated  {not_found} not-in-EPSS  {errors} errors"
            )

        if batch_num < len(batches):
            time.sleep(SLEEP_BETWEEN)

    conn.commit()

    cur.execute("SELECT COUNT(*) FROM threats WHERE epss_score IS NULL")
    null_after = cur.fetchone()[0]
    cur.close()
    conn.close()

    print("\n" + "=" * 60)
    print("EPSS collection complete!")
    print(f"  Updated (scored)   : {updated}")
    print(f"  Not in EPSS yet    : {not_found}  ← expected for very new CVEs")
    print(f"  Errors             : {errors}")
    print(f"  NULL before        : {null_before}")
    print(f"  NULL after         : {null_after}")
    print("=" * 60)


if __name__ == "__main__":
    main()
