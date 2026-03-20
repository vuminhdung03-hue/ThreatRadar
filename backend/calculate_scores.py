"""
Threat Scoring Algorithm - Final Working Version

Author: Dung Vu
Date: March 2026
Course: CSC498 - ThreatRadar Capstone
"""

import psycopg2
from datetime import datetime
import os
from dotenv import load_dotenv
import json

load_dotenv()

def calculate_threat_score(threat):
    """
    Calculate composite threat score
    
    Formula:
    - CVSS (40%): Severity
    - EPSS (30%): Exploit probability  
    - Recency (10%): How new
    - Tech baseline (20%): Fixed baseline for now
    
    Multipliers:
    - KEV: 1.5x (actively exploited!)
    """
    cvss = threat.get('cvss_score', 0) or 0
    epss = threat.get('epss_score', 0) or 0
    is_kev = threat.get('is_kev', False)
    published_date = threat.get('published_date')
    
    # CVSS Component (40%)
    cvss_contribution = (cvss / 10.0) * 0.4
    
    # EPSS Component (30%)
    epss_contribution = (epss / 100.0) * 0.3
    
    # Recency Component (10%)
    recency_score = 0
    if published_date:
        try:
            if isinstance(published_date, str):
                pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            else:
                pub_date = published_date
            
            days_old = (datetime.now(pub_date.tzinfo) - pub_date).days
            recency_score = max(0, 1 - (days_old / 90))
        except:
            recency_score = 0
    
    recency_contribution = recency_score * 0.1
    
    # Tech baseline (20%) - simplified for Checkpoint 2
    tech_contribution = 0.1  # 50% baseline
    
    # Calculate base score
    base_score = (
        cvss_contribution + 
        epss_contribution + 
        tech_contribution + 
        recency_contribution
    )
    
    # Apply KEV multiplier
    multiplier = 1.5 if is_kev else 1.0
    
    # Final score (capped at 1.0)
    final_score = min(base_score * multiplier, 1.0)
    
    return final_score

def calculate_scores_for_environment(environment_id):
    """Calculate scores for all CVEs for one environment"""
    
    try:
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()
        
        # Get environment name
        cur.execute("SELECT name FROM environment_profiles WHERE id = %s", (environment_id,))
        result = cur.fetchone()
        if not result:
            return 0
        
        env_name = result[0]
        print(f"\nCalculating scores for: {env_name}")
        
        # Get all threats
        cur.execute("""
            SELECT 
                cve_id,
                cvss_score,
                epss_score,
                is_kev,
                published_date
            FROM threats
            WHERE cvss_score IS NOT NULL
        """)
        
        threats = cur.fetchall()
        print(f"Processing {len(threats)} CVEs...")
        
        scores_calculated = 0
        
        for cve_id, cvss, epss, kev, pub_date in threats:
            threat = {
                'cvss_score': cvss,
                'epss_score': epss,
                'is_kev': kev,
                'published_date': pub_date
            }
            
            final_score = calculate_threat_score(threat)
            
            try:
                # Insert with correct column name: relevance_score
                cur.execute("""
                    INSERT INTO threat_scores (
                        threat_id,
                        environment_id,
                        relevance_score
                    ) VALUES (%s, %s, %s)
                    ON CONFLICT (threat_id, environment_id) 
                    DO UPDATE SET
                        relevance_score = EXCLUDED.relevance_score,
                        computed_at = CURRENT_TIMESTAMP
                """, (
                    cve_id,
                    environment_id,
                    final_score
                ))
                
                scores_calculated += 1
                
            except Exception as e:
                print(f"✗ Error storing score for {cve_id}: {e}")
                continue
        
        conn.commit()
        cur.close()
        conn.close()
        
        return scores_calculated
        
    except Exception as e:
        print(f"✗ Database error: {e}")
        import traceback
        traceback.print_exc()
        return 0

def show_top_threats(environment_id, limit=10):
    """Display top threats for an environment"""
    
    try:
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()
        
        # Get environment name
        cur.execute("SELECT name FROM environment_profiles WHERE id = %s", (environment_id,))
        env_name = cur.fetchone()[0]
        
        print(f"\n{'=' * 80}")
        print(f"TOP {limit} THREATS FOR: {env_name}")
        print(f"{'=' * 80}")
        
        # Query with correct column name: relevance_score
        cur.execute("""
            SELECT 
                t.cve_id,
                t.cvss_score,
                t.epss_score,
                t.is_kev,
                ts.relevance_score,
                t.description
            FROM threat_scores ts
            JOIN threats t ON ts.threat_id = t.cve_id
            WHERE ts.environment_id = %s
            ORDER BY ts.relevance_score DESC
            LIMIT %s
        """, (environment_id, limit))
        
        threats = cur.fetchall()
        
        print(f"\n{'Rank':<5} {'CVE ID':<18} {'Score':<8} {'CVSS':<7} {'EPSS':<8} {'KEV':<5}")
        print("-" * 80)
        
        for i, (cve_id, cvss, epss, kev, score, desc) in enumerate(threats, 1):
            kev_flag = "✓" if kev else ""
            epss_val = epss if epss else 0
            
            print(f"{i:<5} {cve_id:<18} {score:>6.1%} {cvss:<7.1f} {epss_val:>6.1f}% {kev_flag:<5}")
            
            # Show description for top 3
            if i <= 3:
                short_desc = (desc[:70] + '...') if desc and len(desc) > 70 else (desc or 'No description')
                print(f"      └─ {short_desc}")
        
        print("\nLegend:")
        print("  Score = Threat relevance score (0-100%)")
        print("  CVSS  = Severity (0-10)")
        print("  EPSS  = Exploit probability (0-100%)")
        print("  KEV   = ✓ if actively exploited")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Main scoring function"""
    
    print("=" * 80)
    print("ThreatRadar - Threat Scoring Algorithm")
    print("=" * 80)
    
    try:
        # Get all environments
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()
        
        cur.execute("SELECT id, name FROM environment_profiles ORDER BY name")
        environments = cur.fetchall()
        
        if not environments:
            print("\n✗ No environment profiles found!")
            print("  Run create_environments.py first")
            return
        
        print(f"\nFound {len(environments)} environment profiles:")
        for env_id, env_name in environments:
            print(f"  • {env_name}")
        
        cur.close()
        conn.close()
        
        # Calculate scores for each environment
        total_scores = 0
        
        for env_id, env_name in environments:
            scores = calculate_scores_for_environment(env_id)
            total_scores += scores
            print(f"✓ Calculated {scores} threat scores")
        
        print("\n" + "=" * 80)
        print(f"Scoring complete!")
        print(f"Total scores calculated: {total_scores}")
        print(f"(730 CVEs × {len(environments)} environments = {730 * len(environments)} expected)")
        print("=" * 80)
        
        # Show top threats for each environment
        for env_id, env_name in environments:
            show_top_threats(env_id, limit=5)
        
      
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()