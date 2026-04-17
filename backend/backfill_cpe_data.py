"""
Backfill cpe_data JSONB from affected_products for all existing threats,
then recalculate threat scores for all environments using CPEMatcher.

Run once after the migration adds the cpe_data column:
  python backfill_cpe_data.py
"""

import json
import os
import sys

import psycopg2
from psycopg2.extras import Json
from dotenv import load_dotenv

load_dotenv()

# Allow importing from app/ when run from backend/
sys.path.insert(0, os.path.dirname(__file__))
from app.services.cpe_matcher import CPEMatcher


def _psycopg2_url(raw_url: str) -> str:
    return raw_url.replace('postgresql+asyncpg://', 'postgresql://', 1)


def _priority(score: float) -> str:
    if score >= 0.75:
        return 'CRITICAL'
    if score >= 0.50:
        return 'HIGH'
    if score >= 0.25:
        return 'MEDIUM'
    return 'LOW'


def backfill_cpe_data(conn) -> int:
    """Populate cpe_data from affected_products for threats where it is NULL."""
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) FROM threats
        WHERE cpe_data IS NULL
          AND affected_products IS NOT NULL
          AND array_length(affected_products, 1) > 0
    """)
    total = cur.fetchone()[0]
    print(f"Threats needing cpe_data backfill: {total}")

    if total == 0:
        cur.close()
        return 0

    cur.execute("""
        SELECT cve_id, affected_products FROM threats
        WHERE cpe_data IS NULL
          AND affected_products IS NOT NULL
          AND array_length(affected_products, 1) > 0
    """)
    rows = cur.fetchall()

    updated = 0
    for cve_id, affected_products in rows:
        cpe_entries = []
        seen = set()
        for prod in (affected_products or []):
            if ':' in prod:
                vendor, product = prod.split(':', 1)
                key = (vendor, product)
                if key not in seen:
                    seen.add(key)
                    cpe_entries.append({"vendor": vendor, "product": product})

        if not cpe_entries:
            continue

        cur.execute(
            "UPDATE threats SET cpe_data = %s WHERE cve_id = %s",
            (Json(cpe_entries), cve_id),
        )
        updated += 1

        if updated % 2000 == 0:
            conn.commit()
            print(f"  {updated}/{total} backfilled...")

    conn.commit()
    cur.close()
    print(f"✓ cpe_data backfilled for {updated} threats")
    return updated


def recalculate_scores(conn) -> dict[int, int]:
    """
    Recalculate composite scores for all threats × all environments.
    Uses CPEMatcher for tech matching. Returns {env_id: upserted_count}.
    """
    from datetime import datetime

    cur = conn.cursor()

    # Fetch all environments
    cur.execute("SELECT id, name, technologies FROM environment_profiles ORDER BY id")
    environments = cur.fetchall()
    print(f"\nRecalculating scores for {len(environments)} environments...")

    totals: dict[int, int] = {}

    for env_id, env_name, env_technologies in environments:
        env_techs = list(env_technologies or [])
        print(f"\n  [{env_name}] — {len(env_techs)} env technologies")

        cur.execute("""
            SELECT cve_id, cvss_score, epss_score,
                   (in_cisa_kev OR in_vulncheck_kev) AS is_kev,
                   published_date, cpe_data, technologies
            FROM threats
        """)
        threats = cur.fetchall()
        print(f"    Scoring {len(threats)} threats...")

        upserted = 0
        for cve_id, cvss, epss, is_kev, pub_date, cpe_data, techs in threats:
            if cpe_data:
                matches, match_score = CPEMatcher.count_matches(env_techs, cpe_data)
            else:
                synthetic = [
                    {"vendor": p.split(':')[0], "product": p.split(':')[1]}
                    for p in (techs or [])
                    if ':' in p
                ]
                matches, match_score = CPEMatcher.count_matches(env_techs, synthetic)

            # Scoring formula (mirrors scoring.py)
            cvss_c = ((cvss or 0) / 10.0) * 0.4
            epss_c = (epss or 0) * 0.3

            recency = 0.0
            if pub_date:
                days_old = (datetime.now(pub_date.tzinfo) - pub_date).days
                recency = max(0.0, 1.0 - (days_old / 90))
            recency_c = recency * 0.1

            tech_c = min(match_score, 1.0) * 0.2

            base = cvss_c + epss_c + tech_c + recency_c
            multiplier = 1.5 if is_kev else 1.0
            final = min(base * multiplier, 1.0)
            priority = _priority(final)

            breakdown = {
                "cvss_contribution": round(cvss_c, 4),
                "epss_contribution": round(epss_c, 4),
                "tech_contribution": round(tech_c, 4),
                "recency_contribution": round(recency_c, 4),
                "kev_multiplier": multiplier,
                "base_score": round(base, 4),
                "final_score": round(final, 4),
                "tech_match_count": matches,
                "tech_match_score": round(match_score, 4),
            }

            try:
                cur.execute("""
                    INSERT INTO threat_scores
                        (threat_id, environment_id, composite_score, priority_level,
                         tech_match_count, score_breakdown, calculated_at)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb, NOW())
                    ON CONFLICT (threat_id, environment_id) DO UPDATE SET
                        composite_score  = EXCLUDED.composite_score,
                        priority_level   = EXCLUDED.priority_level,
                        tech_match_count = EXCLUDED.tech_match_count,
                        score_breakdown  = EXCLUDED.score_breakdown,
                        calculated_at    = NOW()
                """, (cve_id, env_id, final, priority, matches, json.dumps(breakdown)))
                upserted += 1
            except Exception as e:
                print(f"    ✗ Error scoring {cve_id}: {e}")
                conn.rollback()
                continue

            if upserted % 2000 == 0:
                conn.commit()
                print(f"    {upserted}/{len(threats)}...")

        conn.commit()
        totals[env_id] = upserted
        print(f"  ✓ {upserted} scores upserted for {env_name}")

    cur.close()
    return totals


def show_results(conn) -> None:
    """Print before/after comparison of tech_match_count > 0."""
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM threat_scores WHERE tech_match_count > 0")
    matched = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM threat_scores")
    total = cur.fetchone()[0]
    print(f"\n{'='*60}")
    print(f"tech_match_count > 0 : {matched} / {total} scores ({matched/total*100:.1f}%)")

    print("\nTop 10 Healthcare threats by composite score:")
    cur.execute("""
        SELECT t.cve_id, ts.composite_score, ts.tech_match_count,
               ts.priority_level, t.cvss_score
        FROM threat_scores ts
        JOIN threats t ON ts.threat_id = t.cve_id
        WHERE ts.environment_id = 1
        ORDER BY ts.composite_score DESC
        LIMIT 10
    """)
    rows = cur.fetchall()
    print(f"  {'CVE ID':<20} {'Score':>6}  {'CVSS':>5}  {'Matches':>7}  Priority")
    print(f"  {'-'*20} {'-'*6}  {'-'*5}  {'-'*7}  --------")
    for cve_id, score, matches, priority, cvss in rows:
        print(f"  {cve_id:<20} {score:>6.1%}  {(cvss or 0):>5.1f}  {matches:>7}  {priority}")

    cur.close()


def main() -> None:
    print("=" * 60)
    print("ThreatRadar — CPE Data Backfill + Score Recalculation")
    print("=" * 60)

    db_url = _psycopg2_url(os.getenv('DATABASE_URL', ''))
    try:
        conn = psycopg2.connect(db_url)
    except Exception as e:
        print(f"✗ DB connection failed: {e}")
        return

    backfill_cpe_data(conn)
    totals = recalculate_scores(conn)

    print(f"\n{'='*60}")
    print("Score recalculation complete")
    for env_id, count in totals.items():
        print(f"  env {env_id}: {count} rows upserted")

    show_results(conn)
    conn.close()


if __name__ == "__main__":
    main()
