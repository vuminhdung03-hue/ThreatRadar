import requests
import time
from database import get_connection

EPSS_API_URL = "https://api.first.org/data/v1/epss"

def fetch_epss_score(cve_id):
    """
    Fetch EPSS score for a single CVE
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2026-27941')
    
    Returns:
        float: EPSS score (0-100 scale) or None if not found
    """
    try:
        params = {"cve": cve_id}
        response = requests.get(EPSS_API_URL, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('status') == 'OK' and data.get('data'):
            epss_value = float(data['data'][0]['epss'])
            # Convert 0.0-1.0 to 0-100 scale
            return epss_value * 100
        
        return None
        
    except Exception as e:
        print(f"  ✗ Error fetching EPSS for {cve_id}: {e}")
        return None

def update_threat_epss(conn, cve_id, epss_score):
    """Update a threat with its EPSS score"""
    cursor = conn.cursor()
    
    query = "UPDATE threats SET epss_score = %s WHERE cve_id = %s;"
    cursor.execute(query, (epss_score, cve_id))
    
    conn.commit()
    cursor.close()

def get_all_cve_ids(conn):
    """Get list of all CVE IDs in database"""
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
        print(f"✗ Database connection failed: {e}")
        return
    
    # Get all CVE IDs
    cve_ids = get_all_cve_ids(conn)
    print(f"Found {len(cve_ids)} CVEs to process")
    
    # Fetch EPSS for each CVE
    updated = 0
    skipped = 0
    
    print("\nFetching EPSS scores...")
    for i, cve_id in enumerate(cve_ids, 1):
        print(f"[{i}/{len(cve_ids)}] {cve_id}...", end=" ")
        
        epss_score = fetch_epss_score(cve_id)
        
        if epss_score is not None:
            update_threat_epss(conn, cve_id, epss_score)
            print(f"✓ EPSS: {epss_score:.2f}%")
            updated += 1
        else:
            print("✗ Not found")
            skipped += 1
        
        # Rate limiting - be nice to the API
        time.sleep(1)  # 1 second between requests
    
    print("\n" + "=" * 60)
    print(f"EPSS collection complete!")
    print(f"  Updated: {updated} CVEs")
    print(f"  Skipped: {skipped} CVEs")
    print("=" * 60)
    
    conn.close()

if __name__ == "__main__":
    main()