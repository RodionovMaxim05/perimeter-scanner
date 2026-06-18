DROP INDEX IF EXISTS idx_svc_vulns_service;

DROP INDEX IF EXISTS idx_scan_services_scan;

DROP INDEX IF EXISTS idx_host_scans_ip_time;

DROP TABLE IF EXISTS service_vulnerabilities;

DROP TABLE IF EXISTS services;

DROP TABLE IF EXISTS host_scans;

DROP TABLE IF EXISTS vulnerabilities;

DROP TABLE IF EXISTS severities;