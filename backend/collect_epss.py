import requests
import time
from database import get_connection

# FIRST.org EPSS API endpoint - found this in their documentation
EPSS_API_URL = "https://api.first.org/data/v1/epss"

def fetch_epss_score(cve_id):
    """
    Fetch EPSS score for a single CVE from FIRST.org
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2026-27941')
    
    Returns:
        float: EPSS score (0-100 scale) or None if not found
    """
    try:
        params = {"cve": cve_id}
        # Using 10 sec timeout - API can be slow sometimes
        response = requests.get(EPSS_API_URL, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        # Check if we got valid data back
        if data.get('status') == 'OK' and data.get('data'):
            entry = data['data'][0]
            epss_value = float(entry['epss'])
            percentile_value = float(entry.get('percentile', 0))
            # API returns 0.0-1.0 scale; store as-is
            return epss_value, percentile_value

        return None, None
        
    except Exception as e:
        # Some CVEs are too new to have EPSS scores yet
        print(f"  Couldn't fetch EPSS for {cve_id}: {e}")
        return None

def update_threat_epss(conn, cve_id, epss_score, epss_percentile):
    """Update a threat with its EPSS score and percentile in database"""
    cursor = conn.cursor()

    query = "UPDATE threats SET epss_score = %s, epss_percentile = %s WHERE cve_id = %s;"
    cursor.execute(query, (epss_score, epss_percentile, cve_id))

    conn.commit()
    cursor.close()

def get_all_cve_ids(conn):
    """Get list of all CVE IDs currently in database"""
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id FROM threats;")
    cve_ids = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return cve_ids

def main():
    """Main EPSS collection function"""
    print("=" * 60)
    print("ThreatRadar - EPSS Data Collection")
    print("=" * 60)
    
    # Connect to database
    try:
        conn = get_connection()
        print("✓ Connected to database")
    except Exception as e:
        print(f"Database connection failed: {e}")
        return
    
    # Get all CVE IDs from threats table
    cve_ids = get_all_cve_ids(conn)
    print(f"Found {len(cve_ids)} CVEs to process")
    
    # Fetch EPSS for each CVE
    success_count = 0
    failed_count = 0
    
    print("\nFetching EPSS scores from FIRST.org API...")
    for i, cve_id in enumerate(cve_ids, 1):
        print(f"[{i}/{len(cve_ids)}] {cve_id}...", end=" ")
        
        epss_score, epss_percentile = fetch_epss_score(cve_id)

        if epss_score is not None:
            update_threat_epss(conn, cve_id, epss_score, epss_percentile)
            print(f"✓ EPSS: {epss_score:.4f} (p{epss_percentile:.0%})")
            success_count += 1
        else:
            print("✗ Not found")
            failed_count += 1
        
        # Rate limiting - wait 1 second between requests
        # Tried 0.5 seconds first but seemed too aggressive
        # 1 second works fine and is respectful to their free API
        time.sleep(1)
    
    print("\n" + "=" * 60)
    print(f"EPSS collection complete!")
    print(f"  Successfully updated: {success_count} CVEs")
    print(f"  Failed/Not found: {failed_count} CVEs")
    print("=" * 60)
    
    conn.close()

if __name__ == "__main__":
    main()