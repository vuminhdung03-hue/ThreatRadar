"""
CISA KEV (Known Exploited Vulnerabilities) Data Collector
Fetches actively exploited CVEs from CISA's catalog and flags them in our database

Author: Dung Vu
Date: March 13, 2026
Course: CSC498 - ThreatRadar Capstone
"""

import requests
import psycopg2
from psycopg2.extras import execute_values
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# CISA KEV JSON feed - this is public, no API key needed
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev_catalog():
    """
    Fetch the KEV catalog from CISA
    
    Returns:
        dict: Full KEV catalog with vulnerabilities list
    """
    print("Fetching CISA KEV catalog...")
    
    try:
        # Make request to CISA API
        response = requests.get(KEV_URL, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        print(f"✓ KEV catalog version: {data['catalogVersion']}")
        print(f"✓ Released: {data['dateReleased']}")
        print(f"✓ Total KEV entries: {len(data['vulnerabilities'])}")
        
        return data
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Error fetching KEV catalog: {e}")
        return None

def extract_kev_cves(kev_data):
    """
    Extract just the CVE IDs from the KEV catalog
    
    Args:
        kev_data: Full KEV catalog JSON
    
    Returns:
        set: Set of CVE IDs that are on the KEV list
    """
    if not kev_data or 'vulnerabilities' not in kev_data:
        return set()
    
    # Extract CVE IDs - using a set for fast lookup
    # NOTE: Some KEV entries might not have CVE IDs (rare), so we filter those out
    kev_cves = {
        vuln['cveID'] 
        for vuln in kev_data['vulnerabilities'] 
        if 'cveID' in vuln and vuln['cveID'].startswith('CVE-')
    }
    
    print(f"✓ Extracted {len(kev_cves)} unique CVE IDs from KEV catalog")
    
    return kev_cves

def update_kev_flags(kev_cves):
    """
    Update database to flag CVEs that are on the KEV list
    
    Args:
        kev_cves: Set of CVE IDs from KEV catalog
    
    Returns:
        int: Number of CVEs flagged as KEV
    """
    if not kev_cves:
        print("No KEV CVEs to update")
        return 0
    
    print("\nUpdating KEV flags in database...")
    
    try:
        # Connect to database
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()
        
        # First, reset all KEV flags to FALSE
        # (in case a CVE was removed from the KEV list)
        cur.execute("UPDATE threats SET is_kev = FALSE")
        
        # Get all CVEs currently in our database
        cur.execute("SELECT cve_id FROM threats")
        db_cves = [row[0] for row in cur.fetchall()]
        
        print(f"✓ Found {len(db_cves)} CVEs in database")
        
        # Find which of our CVEs are on the KEV list
        # Using set intersection for efficiency
        matched_cves = set(db_cves) & kev_cves
        
        if matched_cves:
            print(f"✓ Found {len(matched_cves)} CVEs that are on the KEV list!")
            
            # Update is_kev flag for matched CVEs
            # Using ANY for efficient bulk update
            cur.execute(
                "UPDATE threats SET is_kev = TRUE WHERE cve_id = ANY(%s)",
                (list(matched_cves),)
            )
            
            # Show which CVEs were flagged
            print("\nCVEs flagged as actively exploited:")
            cur.execute(
                """
                SELECT cve_id, cvss_score, description 
                FROM threats 
                WHERE is_kev = TRUE 
                ORDER BY cvss_score DESC
                """
            )
            
            for cve_id, cvss, desc in cur.fetchall():
                # Truncate description to 60 chars for readability
                short_desc = (desc[:57] + '...') if len(desc) > 60 else desc
                print(f"  • {cve_id} (CVSS {cvss:.1f}) - {short_desc}")
        else:
            print("✓ None of our CVEs are currently on the KEV list (good news!)")
        
        # Commit changes
        conn.commit()
        
        # Get final count
        cur.execute("SELECT COUNT(*) FROM threats WHERE is_kev = TRUE")
        kev_count = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return kev_count
        
    except Exception as e:
        print(f"✗ Database error: {e}")
        return 0

def main():
    """
    Main function to orchestrate KEV data collection
    """
    print("=" * 60)
    print("CISA KEV Data Collection")
    print("=" * 60)
    
    # Step 1: Fetch KEV catalog from CISA
    kev_data = fetch_kev_catalog()
    
    if not kev_data:
        print("\n✗ Failed to fetch KEV catalog. Exiting.")
        return
    
    # Step 2: Extract CVE IDs
    kev_cves = extract_kev_cves(kev_data)
    
    # Step 3: Update database
    flagged_count = update_kev_flags(kev_cves)
    
    # Summary
    print("\n" + "=" * 60)
    print(f"KEV collection complete!")
    print(f"Total CVEs on KEV list: {len(kev_cves)}")
    print(f"CVEs in our database flagged as KEV: {flagged_count}")
    print("=" * 60)

if __name__ == "__main__":
    main()