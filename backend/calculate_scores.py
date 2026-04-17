"""
Threat Scoring Algorithm
Calculates composite scores for all threats × all environments.

Author: Dung Vu
Date: March 2026 (updated April 2026)
Course: CSC498 - ThreatRadar Capstone

Usage:
  python calculate_scores.py
"""

import json
import os
import sys

import psycopg2
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Allow importing CPEMatcher from app/ when run from backend/
sys.path.insert(0, os.path.dirname(__file__))
from app.services.cpe_matcher import CPEMatcher

# Fix Unicode output on Windows terminals
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


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


def calculate_threat_score(
    cvss: float,
    epss: float,
    is_kev: bool,
    published_date,
    tech_match_count: int,
    tech_match_score: float,
) -> tuple[float, dict]:
    """
    Composite score formula:
      CVSS     40%  — severity
      EPSS     30%  — exploit probability (stored as 0–1, not 0–100)
      Tech     20%  — environment relevance (continuous CPE match score)
      Recency  10%  — how new the CVE is (decays to 0 after 90 days)
      KEV      1.5× multiplier if actively exploited
    """
    cvss_contribution = (cvss / 10.0) * 0.4
    epss_contribution = epss * 0.3          # EPSS is 0–1, no /100 needed

    recency_score = 0.0
    if published_date:
        try:
            if isinstance(published_date, str):
                pub_dt = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            else:
                pub_dt = published_date
            days_old = (datetime.now(pub_dt.tzinfo) - pub_dt).days
            recency_score = max(0.0, 1.0 - (days_old / 90))
        except Exception:
            pass
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
    return final_score, breakdown


def calculate_scores_for_environment(conn, environment_id: int) -> int:
    """Calculate and upsert scores for all threats in one environment."""
    cur = conn.cursor()

    cur.execute(
        "SELECT name, technologies FROM environment_profiles WHERE id = %s",
        (environment_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        return 0

    env_name, env_technologies = row
    env_techs = list(env_technologies or [])
    print(f"\n  [{env_name}] — {len(env_techs)} env technologies")

    cur.execute("""
        SELECT cve_id, cvss_score, epss_score,
               (in_cisa_kev OR in_vulncheck_kev) AS is_kev,
               published_date, cpe_data, technologies
        FROM threats
    """)
    threats = cur.fetchall()
    total = len(threats)
    print(f"    Scoring {total} threats...")

    scored = skipped = errors = 0

    for i, (cve_id, cvss, epss, is_kev, pub_date, cpe_data, techs) in enumerate(threats, 1):
        if cvss is None:
            skipped += 1
            continue

        # Tech matching — prefer cpe_data JSONB, fall back to technologies TEXT[]
        if cpe_data:
            matches, match_score = CPEMatcher.count_matches(env_techs, cpe_data)
        else:
            synthetic = [
                {"vendor": p.split(':')[0], "product": p.split(':')[1]}
                for p in (techs or []) if ':' in p
            ]
            matches, match_score = CPEMatcher.count_matches(env_techs, synthetic)

        final_score, breakdown = calculate_threat_score(
            cvss or 0,
            epss or 0,
            bool(is_kev),
            pub_date,
            matches,
            match_score,
        )
        priority = _priority(final_score)

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
            """, (cve_id, environment_id, final_score, priority,
                  matches, json.dumps(breakdown)))
            scored += 1
        except Exception as e:
            print(f"    ✗ Error scoring {cve_id}: {e}")
            conn.rollback()
            errors += 1
            continue

        if i % 1000 == 0:
            conn.commit()
            print(f"    {i}/{total}  scored={scored}  skipped={skipped}  errors={errors}")

    conn.commit()
    cur.close()
    print(f"  ✓ {scored} scores upserted  ({skipped} no-CVSS skipped, {errors} errors)")
    return scored


def show_top_threats(conn, environment_id: int, limit: int = 5) -> None:
    cur = conn.cursor()
    cur.execute("SELECT name FROM environment_profiles WHERE id = %s", (environment_id,))
    env_name = cur.fetchone()[0]

    print(f"\n  Top {limit} for {env_name}:")
    print(f"  {'CVE ID':<20} {'Score':>6}  {'CVSS':>5}  {'EPSS':>6}  {'Matches':>7}  Priority")
    print(f"  {'-'*20} {'-'*6}  {'-'*5}  {'-'*6}  {'-'*7}  --------")

    cur.execute("""
        SELECT t.cve_id, ts.composite_score, t.cvss_score,
               t.epss_score, ts.tech_match_count, ts.priority_level
        FROM threat_scores ts
        JOIN threats t ON ts.threat_id = t.cve_id
        WHERE ts.environment_id = %s
        ORDER BY ts.composite_score DESC
        LIMIT %s
    """, (environment_id, limit))

    for cve_id, score, cvss, epss, matches, priority in cur.fetchall():
        epss_pct = f"{(epss or 0)*100:.1f}%"
        print(f"  {cve_id:<20} {score:>6.1%}  {(cvss or 0):>5.1f}  {epss_pct:>6}  {matches:>7}  {priority}")
    cur.close()


def main() -> None:
    print("=" * 70)
    print("ThreatRadar — Threat Scoring Algorithm")
    print("=" * 70)

    db_url = _psycopg2_url(os.getenv('DATABASE_URL', ''))
    try:
        conn = psycopg2.connect(db_url)
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return

    cur = conn.cursor()
    cur.execute("SELECT id, name FROM environment_profiles ORDER BY id")
    environments = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM threats")
    threat_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM threat_scores")
    scores_before = cur.fetchone()[0]
    cur.close()

    print(f"\nThreats in DB         : {threat_count}")
    print(f"threat_scores before  : {scores_before}")
    print(f"Environments          : {len(environments)}")
    print(f"Expected scores       : {threat_count} × {len(environments)} = {threat_count * len(environments)}")

    total_scored = 0
    for env_id, _ in environments:
        scored = calculate_scores_for_environment(conn, env_id)
        total_scored += scored

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM threat_scores")
    scores_after = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM threat_scores WHERE tech_match_count > 0")
    matched = cur.fetchone()[0]
    cur.close()

    print("\n" + "=" * 70)
    print("Scoring complete!")
    print(f"  threat_scores before : {scores_before}")
    print(f"  threat_scores after  : {scores_after}")
    print(f"  tech_match_count > 0 : {matched} / {scores_after}")
    print("=" * 70)

    for env_id, _ in environments:
        show_top_threats(conn, env_id, limit=5)

    conn.close()


if __name__ == "__main__":
    main()
