-- Deduplicated vulnerability catalog
-- One CVE record is reused across all scans that detect it
CREATE TABLE IF NOT EXISTS vulnerabilities(
    id SERIAL PRIMARY KEY,
    cve VARCHAR(50) UNIQUE NOT NULL,
    score NUMERIC(3, 1) CHECK (
        score >= 0.0
        AND score <= 10.0
    ),
    description TEXT,
    exploit_available BOOLEAN DEFAULT FALSE NOT NULL,
    link TEXT
);

-- One record per (host, point-in-time) scan
CREATE TABLE IF NOT EXISTS host_scans (
    id SERIAL PRIMARY KEY,
    ip INET NOT NULL,
    scan_time TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    CONSTRAINT uniq_host_scan_time UNIQUE (ip, scan_time)
);

-- Open ports and services discovered during a specific host scan
CREATE TABLE IF NOT EXISTS scan_services (
    id SERIAL PRIMARY KEY,
    host_scan_id INT NOT NULL REFERENCES host_scans(id) ON DELETE CASCADE,
    port INT NOT NULL CHECK (
        port >= 1
        AND port <= 65535
    ),
    proto VARCHAR(10) NOT NULL DEFAULT 'tcp',
    service VARCHAR(50),
    banner TEXT,
    version VARCHAR(100),
    cpe VARCHAR(255),
    CONSTRAINT uniq_host_port_proto UNIQUE (host_scan_id, port, proto)
);

-- Junction table linking discovered services to known vulnerabilities
CREATE TABLE IF NOT EXISTS scan_service_vulns (
    service_id INT NOT NULL REFERENCES scan_services(id) ON DELETE CASCADE,
    vulnerability_id INT NOT NULL REFERENCES vulnerabilities(id) ON DELETE RESTRICT,
    PRIMARY KEY (service_id, vulnerability_id)
);

-- Fetch all scans for a given IP ordered by time
CREATE INDEX IF NOT EXISTS idx_host_scans_ip_time ON host_scans(ip, scan_time DESC);

-- Fetch all services for a given scan
CREATE INDEX IF NOT EXISTS idx_scan_services_scan ON scan_services(host_scan_id);

-- Fetch all CVEs for a given service
CREATE INDEX IF NOT EXISTS idx_svc_vulns_service ON scan_service_vulns(service_id);