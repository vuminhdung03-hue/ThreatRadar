

import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def backfill():
    conn = psycopg2.connect(os.getenv('DATABASE_URL'))
    cur = conn.cursor()

    # Count rows that need backfill
    cur.execute("""
        SELECT COUNT(*) FROM threats
        WHERE (technologies IS NULL OR array_length(technologies, 1) IS NULL)
          AND affected_products IS NOT NULL
          AND array_length(affected_products, 1) > 0
    """)
    needs_backfill = cur.fetchone()[0]
    print(f"Rows needing backfill: {needs_backfill}")

    # Copy affected_products → technologies
    cur.execute("""
        UPDATE threats
        SET technologies = affected_products
        WHERE (technologies IS NULL OR array_length(technologies, 1) IS NULL)
          AND affected_products IS NOT NULL
          AND array_length(affected_products, 1) > 0
    """)
    updated = cur.rowcount
    conn.commit()
    print(f"Updated {updated} rows")

    # Verify
    cur.execute("SELECT COUNT(*) FROM threats WHERE array_length(technologies, 1) > 0")
    with_tech = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM threats")
    total = cur.fetchone()[0]
    print(f"Threats with technologies: {with_tech} / {total}")

    cur.close()
    conn.close()

if __name__ == "__main__":
    backfill()
