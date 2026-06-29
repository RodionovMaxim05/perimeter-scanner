-- GetHostScanByIP returns the scan record for a given IP.
-- name: GetHostScanByIP :one
SELECT id,
    ip,
    scan_time
FROM host_scans
WHERE ip = $1;

-- GetServicesWithVulnerabilities returns all services with vulnerabilities.
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
    v.exploit_available,
    v.link
FROM scan_services s
    LEFT JOIN scan_service_vulns sv ON s.id = sv.service_id
    LEFT JOIN vulnerabilities v ON sv.vulnerability_id = v.id
WHERE s.host_scan_id = $1;

-- UpsertHostScan inserts a scan record for a host, or updates scan_time if
-- a record for that IP already exists.
-- name: UpsertHostScan :one
INSERT INTO host_scans (ip, scan_time)
VALUES ($1, $2) ON CONFLICT (ip) DO
UPDATE
SET scan_time = EXCLUDED.scan_time
RETURNING id;

-- DeleteServicesByScanID removes all services recorded under a given host scan.
-- name: DeleteServicesByScanID :exec
DELETE FROM scan_services
WHERE host_scan_id = $1;

-- CreateService inserts a discovered open port into a scan record.
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

-- UpsertVulnerability inserts a new CVE or updates it if it already exists.
-- name: UpsertVulnerability :one
INSERT INTO vulnerabilities (
        cve,
        score,
        exploit_available,
        link
    )
VALUES ($1, $2, $3, $4) ON CONFLICT (cve) DO
UPDATE
SET score = EXCLUDED.score,
    exploit_available = EXCLUDED.exploit_available,
    link = EXCLUDED.link
RETURNING id;

-- LinkServiceVuln creates a many-to-many link between a service and a CVE.
-- name: LinkServiceVuln :exec
INSERT INTO scan_service_vulns (service_id, vulnerability_id)
VALUES ($1, $2) ON CONFLICT DO NOTHING;