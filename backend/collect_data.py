"""
NVD CVE Data Collector
Fetches vulnerability data from the National Vulnerability Database
"""

import requests
import psycopg2
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
    Fetch CVEs from NVD API for a given date range
    
    Args:
        start_date: datetime object for start date
        end_date: datetime object for end date
        api_key: Optional NVD API key for higher rate limits
    
    Returns:
        list: List of CVE dictionaries
    """
    # Format dates for NVD API (ISO 8601 format)
    start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.999')
    
    print(f"Fetching CVEs from {start_date_str} to {end_date_str}...")
    print(f"Using API key: {'Yes' if api_key else 'No'}")
    
    # Build request parameters
    params = {
        'pubStartDate': start_date_str,
        'pubEndDate': end_date_str,
        'resultsPerPage': 100  # Max allowed by NVD
    }
    
    # Build headers - API key goes in headers, not params
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    
    all_cves = []
    start_index = 0
    
    try:
        while True:
            # Add pagination
            params['startIndex'] = start_index
            
            # Make request
            response = requests.get(
                NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=30
            )
            
            # Check for errors
            response.raise_for_status()
            
            data = response.json()
            
            # Extract CVEs from response
            vulnerabilities = data.get('vulnerabilities', [])
            
            if not vulnerabilities:
                break
            
            # Process each CVE
            for vuln in vulnerabilities:
                cve = vuln.get('cve', {})
                cve_id = cve.get('id')
                
                if not cve_id:
                    continue
                
                # Extract description
                descriptions = cve.get('descriptions', [])
                description = next(
                    (d['value'] for d in descriptions if d.get('lang') == 'en'),
                    'No description available'
                )
                
                # Extract CVSS score (try v3.1 first, then v3.0, then v2.0)
                cvss_score = None
                cvss_vector = None
                metrics = cve.get('metrics', {})
                
                # Try CVSSv3.1
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString')
                # Try CVSSv3.0
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString')
                # Try CVSSv2.0
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString')
                
                # Extract published date
                published = cve.get('published', '')
                
                # Extract affected products (CPE data)
                affected_products = []
                configurations = cve.get('configurations', [])
                for config in configurations:
                    nodes = config.get('nodes', [])
                    for node in nodes:
                        cpe_matches = node.get('cpeMatch', [])
                        for cpe in cpe_matches:
                            if cpe.get('vulnerable', False):
                                cpe_uri = cpe.get('criteria', '')
                                # Extract product name from CPE
                                # Format: cpe:2.3:a:vendor:product:version:...
                                parts = cpe_uri.split(':')
                                if len(parts) >= 5:
                                    product = f"{parts[3]}:{parts[4]}"
                                    if product not in affected_products:
                                        affected_products.append(product)
                
                all_cves.append({
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'cvss_vector': cvss_vector,
                    'published_date': published,
                    'affected_products': affected_products
                })
            
            print(f"✓ Fetched {len(all_cves)} CVEs so far...")
            
            # Check if there are more results
            total_results = data.get('totalResults', 0)
            if start_index + len(vulnerabilities) >= total_results:
                break
            
            start_index += len(vulnerabilities)
            
            # Rate limiting - be nice to the API
            # With API key: 50 requests/30 seconds = 0.6 sec per request
            # Without API key: 5 requests/30 seconds = 6 sec per request
            time.sleep(0.6 if api_key else 6)
        
        print(f"✓ Total CVEs fetched: {len(all_cves)}")
        return all_cves
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Error fetching from NVD: {e}")
        return []

def store_cves_in_database(cves):
    """
    Store CVE data in PostgreSQL database
    
    Args:
        cves: List of CVE dictionaries
    
    Returns:
        int: Number of CVEs inserted
    """
    if not cves:
        print("No CVEs to store")
        return 0
    
    try:
        # Connect to database
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()
        
        inserted = 0
        skipped = 0
        
        for cve in cves:
            try:
                # Skip if no CVSS score
                if cve['cvss_score'] is None:
                    skipped += 1
                    continue
                
                # Insert CVE (ignore if already exists)
                cur.execute("""
                    INSERT INTO threats (
                        cve_id, 
                        description, 
                        cvss_score,
                        cvss_vector,
                        published_date,
                        affected_products
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO NOTHING
                """, (
                    cve['cve_id'],
                    cve['description'][:500],  # Truncate long descriptions
                    cve['cvss_score'],
                    cve['cvss_vector'],
                    cve['published_date'],
                    cve['affected_products'][:10]  # Limit to 10 products
                ))
                
                if cur.rowcount > 0:
                    inserted += 1
                else:
                    skipped += 1
                    
            except Exception as e:
                print(f"✗ Error inserting {cve['cve_id']}: {e}")
                skipped += 1
                continue
        
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"✓ Inserted {inserted} new CVEs")
        print(f"✓ Skipped {skipped} duplicates or CVEs without CVSS scores")
        
        return inserted
        
    except Exception as e:
        print(f"✗ Database error: {e}")
        return 0

def main():
    """
    Main function to orchestrate CVE data collection
    """
    print("=" * 60)
    print("ThreatRadar - NVD Data Collection")
    print("=" * 60)
    
    # Connect to database and check current count
    try:
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()
        print("✓ Connected to database")
        
        cur.execute("SELECT COUNT(*) FROM threats")
        current_count = cur.fetchone()[0]
        print(f"Current threats in database: {current_count}")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"✗ Database connection error: {e}")
        return
    
    # Get API key from environment
    api_key = os.getenv('NVD_API_KEY')
    
    # Calculate date range
    # Using March 2024 dates since we know they have CVE data
    # NOTE: You can change these dates to fetch different time periods
    end_date = datetime(2024, 3, 15)
    start_date = datetime(2024, 3, 8)
    
    # Fetch CVEs from NVD
    cves = fetch_cves_from_nvd(start_date, end_date, api_key)
    
    if not cves:
        print("No CVEs fetched. Exiting.")
        return
    
    # Store in database
    inserted = store_cves_in_database(cves)
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Collection complete!")
    print(f"CVEs fetched: {len(cves)}")
    print(f"CVEs inserted: {inserted}")
    print("=" * 60)

if __name__ == "__main__":
    main()