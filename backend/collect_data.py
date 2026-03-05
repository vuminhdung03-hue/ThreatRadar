import requests
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from database import get_connection, insert_threat, get_threat_count
import time

load_dotenv()

NVD_API_KEY = os.getenv('NVD_API_KEY')
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_cves(days=7, max_results=100):
    """Fetch CVEs from NVD API"""
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Format dates for NVD API
    pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000")
    pub_end = end_date.strftime("%Y-%m-%dT23:59:59.999")
    
    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": min(max_results, 2000)
    }
    
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    print(f"Fetching CVEs from {pub_start} to {pub_end}...")
    print(f"Using API key: {'Yes' if NVD_API_KEY else 'No (rate limited!)'}")
    
    try:
        response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        
        print(f"✓ Successfully fetched {len(vulnerabilities)} CVEs from NVD")
        return vulnerabilities
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Error fetching from NVD: {e}")
        return []

def parse_cve(vuln_data):
    """Parse CVE data from NVD format"""
    cve = vuln_data.get('cve', {})
    
    # Extract CVE ID
    cve_id = cve.get('id', 'UNKNOWN')
    
    # Extract description
    descriptions = cve.get('descriptions', [])
    description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 'No description')
    
    # Extract CVSS score
    cvss_score = None
    cvss_vector = None
    metrics = cve.get('metrics', {})
    
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
        cvss_score = cvss_data.get('baseScore')
        cvss_vector = cvss_data.get('vectorString')
    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
        cvss_data = metrics['cvssMetricV30'][0]['cvssData']
        cvss_score = cvss_data.get('baseScore')
        cvss_vector = cvss_data.get('vectorString')
    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        cvss_data = metrics['cvssMetricV2'][0]['cvssData']
        cvss_score = cvss_data.get('baseScore')
        cvss_vector = cvss_data.get('vectorString')
    
    # Extract published date
    published = cve.get('published', '')
    published_date = datetime.fromisoformat(published.replace('Z', '+00:00')) if published else None
    
    # Extract affected products
    affected_products = []
    configurations = cve.get('configurations', [])
    for config in configurations:
        for node in config.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if cpe_match.get('vulnerable'):
                    criteria = cpe_match.get('criteria', '')
                    parts = criteria.split(':')
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        affected_products.append(f"{vendor} {product}")
    
    return {
        'cve_id': cve_id,
        'cvss_score': cvss_score,
        'cvss_vector': cvss_vector,
        'description': description[:500],
        'published_date': published_date,
        'affected_products': list(set(affected_products))[:10]
    }

def main():
    """Main data collection function"""
    print("=" * 60)
    print("ThreatRadar - NVD Data Collection")
    print("=" * 60)
    
    # Connect to database
    try:
        conn = get_connection()
        print("✓ Connected to database")
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return
    
    # Show current count
    initial_count = get_threat_count(conn)
    print(f"Current threats in database: {initial_count}")
    
    # Fetch CVEs from NVD
    vulnerabilities = fetch_nvd_cves(days=7, max_results=100)
    
    if not vulnerabilities:
        print("No CVEs fetched. Exiting.")
        conn.close()
        return
    
    # Parse and insert each CVE
    inserted = 0
    skipped = 0
    
    print("\nInserting CVEs into database...")
    for vuln in vulnerabilities:
        try:
            cve_data = parse_cve(vuln)
            
            # Skip if no CVSS score
            if cve_data['cvss_score'] is None:
                skipped += 1
                continue
            
            # Insert into database
            if insert_threat(conn, cve_data):
                inserted += 1
                print(f"  ✓ {cve_data['cve_id']} (CVSS: {cve_data['cvss_score']})")
            else:
                skipped += 1
                
        except Exception as e:
            print(f"  ✗ Error processing CVE: {e}")
            skipped += 1
    
    # Final count
    final_count = get_threat_count(conn)
    
    print("\n" + "=" * 60)
    print(f"Collection complete!")
    print(f"  Inserted: {inserted} new CVEs")
    print(f"  Skipped: {skipped} CVEs")
    print(f"  Total in database: {final_count}")
    print("=" * 60)
    
    conn.close()

if __name__ == "__main__":
    main()