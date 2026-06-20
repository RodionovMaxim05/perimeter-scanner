package domain

import "time"

// Vulnerability describes the vulnerability found
type Vulnerability struct {
	CVE              string  `json:"id"`
	Score            float64 `json:"score"`
	Description      string  `json:"description"`
	ExploitAvailable bool    `json:"exploit_available"`
	Link             string  `json:"link"`
}

// ServiceInfo contains information about the service on the port
type ServiceInfo struct {
	Port            int             `json:"port"`
	Proto           string          `json:"proto"`
	Service         string          `json:"service"`
	Banner          string          `json:"banner"`
	Version         string          `json:"version"`
	CPE             string          `json:"cpe,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// HostScanResult represents the final state of the host after scanning
type HostScanResult struct {
	IP       string        `json:"ip"`
	ScanTime time.Time     `json:"scan_time"`
	Services []ServiceInfo `json:"services"`
}

// ScanDiff describes the difference between the current and last scan
type ScanDiff struct {
	IP          string        `json:"ip"`
	NewServices []ServiceInfo `json:"new_services"`
}
