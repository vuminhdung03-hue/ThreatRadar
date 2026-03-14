-- ThreatRadar Checkpoint 1 Demo Queries

-- 1. Total count of threats
SELECT COUNT(*) as total_threats FROM threats;

-- 2. Count by severity level
WITH severity_data AS (
    SELECT 
        CASE 
            WHEN cvss_score >= 9.0 THEN 'Critical'
            WHEN cvss_score >= 7.0 THEN 'High'
            WHEN cvss_score >= 4.0 THEN 'Medium'
            ELSE 'Low'
        END as severity,
        CASE 
            WHEN cvss_score >= 9.0 THEN 1
            WHEN cvss_score >= 7.0 THEN 2
            WHEN cvss_score >= 4.0 THEN 3
            ELSE 4
        END as severity_order
    FROM threats
)
SELECT severity, COUNT(*) as count
FROM severity_data
GROUP BY severity, severity_order
ORDER BY severity_order;

-- 3. Count by day for last 7 days
SELECT 
    DATE(published_date) as day,
    COUNT(*) as count
FROM threats
WHERE published_date >= NOW() - INTERVAL '7 days'
GROUP BY DATE(published_date)
ORDER BY day DESC;

-- 4. Top 10 threats by CVSS score
SELECT 
    cve_id,
    cvss_score,
    LEFT(description, 100) as description_preview
FROM threats
ORDER BY cvss_score DESC
LIMIT 10;

-- 5. Sample of threats with details
SELECT 
    cve_id,
    cvss_score,
    cvss_vector,
    published_date,
    affected_products
FROM threats
LIMIT 10;