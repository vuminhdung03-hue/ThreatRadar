"""
Environment Profiles Creator
Sets up sample environment profiles for different organization types

Author: Dung Vu
Date: March 2026
Course: CSC498 - ThreatRadar Capstone
"""

import psycopg2
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Sample environment profiles
ENVIRONMENTS = [
    {
        'name': 'Healthcare - Regional Hospital',
        'description': 'Mid-sized regional hospital with electronic health records system. Focus: patient data protection and HIPAA compliance.',
        'technologies': [
            'microsoft:windows_server',
            'microsoft:sql_server',
            'epic:emr',
            'cisco:network',
            'vmware:vsphere',
            'microsoft:exchange',
            'citrix:xenapp',
            'apache:http_server'
        ]
    },
    {
        'name': 'E-commerce - Online Retailer',
        'description': 'High-traffic e-commerce platform with real-time transactions. Focus: payment security, uptime, and customer data protection.',
        'technologies': [
            'canonical:ubuntu',
            'nodejs:node.js',
            'facebook:react',
            'postgresql:postgresql',
            'nginx:nginx',
            'redis:redis',
            'stripe:payment_api',
            'amazon:aws'
        ]
    },
    {
        'name': 'Financial Services - Investment Firm',
        'description': 'Investment management firm with strict regulatory compliance requirements. Focus: regulatory compliance, data integrity, audit trails.',
        'technologies': [
            'redhat:enterprise_linux',
            'oracle:database',
            'oracle:java',
            'ibm:websphere',
            'cisco:firewall',
            'splunk:enterprise',
            'vmware:vsphere',
            'microsoft:active_directory'
        ]
    }
]

def create_environment_profiles():
    """
    Create sample environment profiles in the database
    
    Returns:
        int: Number of profiles created
    """
    print("=" * 60)
    print("ThreatRadar - Environment Profile Setup")
    print("=" * 60)
    
    try:
        # Connect to database
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()
        
        print("\nCreating environment profiles...")
        
        created = 0
        
        for env in ENVIRONMENTS:
            try:
                # Insert environment profile
                cur.execute("""
                    INSERT INTO environment_profiles (
                        name,
                        description,
                        technologies
                    ) VALUES (%s, %s, %s)
                    ON CONFLICT (name) DO UPDATE SET
                        description = EXCLUDED.description,
                        technologies = EXCLUDED.technologies
                    RETURNING id
                """, (
                    env['name'],
                    env['description'],
                    env['technologies']
                ))
                
                env_id = cur.fetchone()[0]
                created += 1
                
                print(f"\n✓ Created: {env['name']}")
                print(f"  ID: {env_id}")
                print(f"  Technologies: {len(env['technologies'])} items")
                
                # Show the technologies
                print(f"  Tech stack:")
                for tech in env['technologies'][:5]:  # Show first 5
                    vendor, product = tech.split(':')
                    print(f"    • {vendor} {product}")
                if len(env['technologies']) > 5:
                    print(f"    • ... and {len(env['technologies']) - 5} more")
                    
            except Exception as e:
                print(f"\n✗ Error creating {env['name']}: {e}")
                continue
        
        conn.commit()
        
        # Show summary
        print("\n" + "=" * 60)
        print(f"Environment profile setup complete!")
        print(f"Created/updated {created} environment profiles")
        print("=" * 60)
        
        # Show what's in the database now
        print("\nVerifying profiles in database...")
        cur.execute("SELECT id, name, array_length(technologies, 1) FROM environment_profiles")
        profiles = cur.fetchall()
        
        print(f"\nTotal profiles in database: {len(profiles)}")
        for profile_id, name, tech_count in profiles:
            print(f"  • {name} ({tech_count} technologies)")
        
        cur.close()
        conn.close()
        
        return created
        
    except Exception as e:
        print(f"\n✗ Database error: {e}")
        import traceback
        traceback.print_exc()
        return 0

def main():
    """
    Main function
    """
    created = create_environment_profiles()
    
    if created > 0:
        print("\n" + "=" * 60)
        print("Next steps:")
        print("1. Run calculate_scores.py to generate threat scores")
        print("2. Scores will be calculated for each environment")
        print("3. Same CVE will have different priorities per environment!")
        print("=" * 60)

if __name__ == "__main__":
    main()