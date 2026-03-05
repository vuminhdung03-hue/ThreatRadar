-- ThreatRadar Database Schema

-- Threats table (stores CVE data)
CREATE TABLE IF NOT EXISTS threats (
    cve_id VARCHAR(20) PRIMARY KEY,
    cvss_score FLOAT,
    cvss_vector VARCHAR(100),
    epss_score FLOAT,
    description TEXT,
    published_date TIMESTAMP,
    is_kev BOOLEAN DEFAULT FALSE,
    affected_products TEXT[],
    created_at TIMESTAMP DEFAULT NOW()
);

-- Environment profiles table
CREATE TABLE IF NOT EXISTS environment_profiles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    technologies TEXT[],
    created_at TIMESTAMP DEFAULT NOW()
);

-- Threat scores table
CREATE TABLE IF NOT EXISTS threat_scores (
    id SERIAL PRIMARY KEY,
    threat_id VARCHAR(20) REFERENCES threats(cve_id) ON DELETE CASCADE,
    environment_id INTEGER REFERENCES environment_profiles(id) ON DELETE CASCADE,
    relevance_score FLOAT CHECK (relevance_score >= 0 AND relevance_score <= 1),
    computed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(threat_id, environment_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_threats_published ON threats(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_threats_cvss ON threats(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_scores_env ON threat_scores(environment_id, relevance_score DESC);