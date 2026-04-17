"""
NVD CVE Data Collector
Fetches vulnerability data from the National Vulnerability Database
"""

import json
import requests
import psycopg2
from psycopg2.extras import Json
from datetime import datetime, timedelta
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# NVD API Configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves_from_nvd(start_date, end_date, api_key=None):
    """
    Fetch CVEs from NVD API for a given date range with pagination.
    Uses resultsPerPage=2000 (NVD max) to minimise request count.
    Sleeps 6 seconds between paginated requests to respect rate limits.
    """
    start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.999')

    print(f"Fetching CVEs from {start_date_str} to {end_date_str}...")
    print(f"Using API key: {'Yes' if api_key else 'No (slower rate limit)'}")

    params = {
        'pubStartDate': start_date_str,
        'pubEndDate': end_date_str,
        'resultsPerPage': 2000,
    }
    headers = {'apiKey': api_key} if api_key else {}

    all_cves = []
    start_index = 0
    page_num = 0

    try:
        while True:
            page_num += 1
            params['startIndex'] = start_index

            response = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()

            total_results = data.get('totalResults', 0)
            vulnerabilities = data.get('vulnerabilities', [])

            if page_num == 1:
                print(f"NVD reports {total_results} total CVEs in range")

            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                cve = vuln.get('cve', {})
                cve_id = cve.get('id')
                if not cve_id:
                    continue

                descriptions = cve.get('descriptions', [])
                description = next(
                    (d['value'] for d in descriptions if d.get('lang') == 'en'),
                    'No description available'
                )

                cvss_score = None
                cvss_vector = None
                metrics = cve.get('metrics', {})
                if metrics.get('cvssMetricV31'):
                    d = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score, cvss_vector = d.get('baseScore'), d.get('vectorString')
                elif metrics.get('cvssMetricV30'):
                    d = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score, cvss_vector = d.get('baseScore'), d.get('vectorString')
                elif metrics.get('cvssMetricV2'):
                    d = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score, cvss_vector = d.get('baseScore'), d.get('vectorString')

                affected_products = []
                cpe_data = []
                seen_products = set()
                seen_cpe_keys = set()
                for config in cve.get('configurations', []):
                    for node in config.get('nodes', []):
                        for cpe in node.get('cpeMatch', []):
                            if cpe.get('vulnerable', False):
                                parts = cpe.get('criteria', '').split(':')
                                if len(parts) >= 5:
                                    vendor, product = parts[3], parts[4]
                                    prod_key = f"{vendor}:{product}"
                                    if prod_key not in seen_products:
                                        seen_products.add(prod_key)
                                        affected_products.append(prod_key)
                                    cpe_key = (vendor, product)
                                    if cpe_key not in seen_cpe_keys:
                                        seen_cpe_keys.add(cpe_key)
                                        cpe_data.append({"vendor": vendor, "product": product})

                all_cves.append({
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'cvss_vector': cvss_vector,
                    'published_date': cve.get('published', ''),
                    'affected_products': affected_products,
                    'cpe_data': cpe_data,
                })

            fetched_so_far = start_index + len(vulnerabilities)
            print(f"  Page {page_num}: fetched {len(vulnerabilities)} CVEs "
                  f"({fetched_so_far}/{total_results})")

            if fetched_so_far >= total_results:
                break

            start_index = fetched_so_far
            print(f"  Sleeping 6s before next page...")
            time.sleep(6)

        print(f"✓ Total CVEs fetched: {len(all_cves)}")
        return all_cves

    except requests.exceptions.RequestException as e:
        print(f"✗ Error fetching from NVD: {e}")
        return []

def _psycopg2_url(raw_url):
    """Strip +asyncpg driver prefix so psycopg2 can connect."""
    return raw_url.replace('postgresql+asyncpg://', 'postgresql://', 1)


def store_cves_in_database(cves):
    """
    Upsert CVEs into PostgreSQL.
    ON CONFLICT DO UPDATE refreshes description/cvss fields for existing rows.
    Preserves epss_score, in_cisa_kev, technologies set by other collectors.
    Prints progress every 100 CVEs processed.
    Returns (inserted, updated, skipped_no_cvss).
    """
    if not cves:
        print("No CVEs to store")
        return 0, 0, 0

    try:
        conn = psycopg2.connect(_psycopg2_url(os.getenv('DATABASE_URL')))
        cur = conn.cursor()

        inserted = updated = skipped = 0

        for i, cve in enumerate(cves, 1):
            if cve['cvss_score'] is None:
                skipped += 1
                if i % 100 == 0:
                    print(f"  Progress: {i}/{len(cves)} processed "
                          f"(+{inserted} new, ~{updated} updated, {skipped} skipped)")
                continue

            try:
                cur.execute("""
                    INSERT INTO threats (
                        cve_id, description, cvss_score, cvss_vector,
                        published_date, affected_products, technologies, cpe_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        description       = EXCLUDED.description,
                        cvss_score        = EXCLUDED.cvss_score,
                        cvss_vector       = EXCLUDED.cvss_vector,
                        published_date    = EXCLUDED.published_date,
                        affected_products = EXCLUDED.affected_products,
                        cpe_data          = EXCLUDED.cpe_data
                    RETURNING (xmax = 0) AS is_new
                """, (
                    cve['cve_id'],
                    cve['description'][:500],
                    cve['cvss_score'],
                    cve['cvss_vector'],
                    cve['published_date'],
                    cve['affected_products'][:10],
                    cve['affected_products'][:10],
                    Json(cve['cpe_data'][:20]) if cve['cpe_data'] else None,
                ))

                row = cur.fetchone()
                if row and row[0]:
                    inserted += 1
                else:
                    updated += 1

            except Exception as e:
                print(f"✗ Error upserting {cve['cve_id']}: {e}")
                conn.rollback()
                skipped += 1
                continue

            if i % 100 == 0:
                conn.commit()
                print(f"  Progress: {i}/{len(cves)} processed "
                      f"(+{inserted} new, ~{updated} updated, {skipped} skipped)")

        conn.commit()
        cur.close()
        conn.close()

        print(f"✓ Inserted {inserted} new CVEs")
        print(f"✓ Updated  {updated} existing CVEs")
        print(f"✓ Skipped  {skipped} (no CVSS score or error)")

        return inserted, updated, skipped

    except Exception as e:
        print(f"✗ Database error: {e}")
        return 0, 0, 0

def main():
    print("=" * 60)
    print("ThreatRadar - NVD Data Collection")
    print("=" * 60)

    db_url = _psycopg2_url(os.getenv('DATABASE_URL', ''))
    try:
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threats")
        count_before = cur.fetchone()[0]
        print(f"✓ Connected to database  (threats before: {count_before})")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"✗ Database connection error: {e}")
        return

    api_key = os.getenv('NVD_API_KEY')

    # Dynamic 90-day window ending today
    end_date = datetime.now()
    start_date = end_date - timedelta(days=90)

    cves = fetch_cves_from_nvd(start_date, end_date, api_key)
    if not cves:
        print("No CVEs fetched. Exiting.")
        return

    inserted, updated, skipped = store_cves_in_database(cves)

    # Final DB count
    try:
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threats")
        count_after = cur.fetchone()[0]
        cur.close()
        conn.close()
    except Exception:
        count_after = '?'

    print("\n" + "=" * 60)
    print("Collection complete!")
    print(f"  CVEs fetched from NVD : {len(cves)}")
    print(f"  New (inserted)        : {inserted}")
    print(f"  Existing (updated)    : {updated}")
    print(f"  Skipped (no CVSS)     : {skipped}")
    print(f"  DB threats before     : {count_before}")
    print(f"  DB threats after      : {count_after}")
    print("=" * 60)

if __name__ == "__main__":
    main()