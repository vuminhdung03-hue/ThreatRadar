import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    """Create database connection"""
    return psycopg2.connect(os.getenv('DATABASE_URL'))

def insert_threat(conn, cve_data):
    """Insert a single threat into database"""
    cursor = conn.cursor()

    query = """
    INSERT INTO threats (cve_id, cvss_score, cvss_vector, description, published_date, affected_products)
    VALUES (%s, %s, %s, %s, %s, %s::TEXT[])
    ON CONFLICT (cve_id) DO NOTHING
    RETURNING cve_id;
    """

    try:
        cursor.execute(query, (
            cve_data['cve_id'],
            cve_data.get('cvss_score'),
            cve_data.get('cvss_vector'),
            cve_data.get('description'),
            cve_data.get('published_date'),
            cve_data.get('affected_products') or []
        ))

        result = cursor.fetchone()
        conn.commit()
        cursor.close()
        return result is not None
    except Exception:
        conn.rollback()
        cursor.close()
        raise

def get_threat_count(conn):
    """Get total count of threats"""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM threats;")
    count = cursor.fetchone()[0]
    cursor.close()
    return count