-- ListSeverities returns all severities
-- name: ListSeverities :many
SELECT id,
    name
FROM severities;

-- GetLastHostScan returns the most recent scan record for a given IP
-- name: GetLastHostScan :one
SELECT id,
    ip,
    scan_time
FROM host_scans
WHERE ip = $1
ORDER BY scan_time DESC
LIMIT 1;

-- GetServicesByScanID returns all open ports discovered during a specific scan
-- name: GetServicesByScanID :many
SELECT id,
    host_scan_id,
    port,
    proto,
    service,
    banner,
    version,
    cpe
FROM scan_services
WHERE host_scan_id = $1;

-- GetServicesWithVulnerabilities returns all services with vulnerabilities
-- name: GetServicesWithVulnerabilities :many
SELECT s.id AS service_id,
    s.port,
    s.proto,
    s.service,
    s.banner,
    s.version,
    s.cpe,
    v.cve,
    v.score,
    sev.name AS severity,
    v.description,
    v.exploit_available,
    v.link
FROM scan_services s
    LEFT JOIN scan_service_vulns sv ON s.id = sv.service_id
    LEFT JOIN vulnerabilities v ON sv.vulnerability_id = v.id
    LEFT JOIN severities sev ON v.severity_id = sev.id
WHERE s.host_scan_id = $1;

-- CreateHostScan inserts a new scan record for a host and returns its ID
-- name: CreateHostScan :one
INSERT INTO host_scans (ip, scan_time)
VALUES ($1, $2)
RETURNING id;

-- CreateService inserts a discovered open port into a scan record
-- name: CreateService :one
INSERT INTO scan_services (
        host_scan_id,
        port,
        proto,
        service,
        banner,
        version,
        cpe
    )
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id;

-- UpsertVulnerability inserts a new CVE or updates it if it already exists
-- name: UpsertVulnerability :one
INSERT INTO vulnerabilities (
        cve,
        score,
        severity_id,
        description,
        exploit_available,
        link
    )
VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (cve) DO
UPDATE
SET score = EXCLUDED.score,
    severity_id = EXCLUDED.severity_id,
    description = EXCLUDED.description,
    exploit_available = EXCLUDED.exploit_available,
    link = EXCLUDED.link
RETURNING id;

-- LinkServiceVuln creates a many-to-many link between a service and a CVE
-- name: LinkServiceVuln :exec
INSERT INTO scan_service_vulns (service_id, vulnerability_id)
VALUES ($1, $2) ON CONFLICT DO NOTHING;