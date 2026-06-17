package domain

import "context"

// NetworkScanner defines a contract for the primary fast scan (Masscan)
type NetworkScanner interface {
	// Scan takes a list of targets and returns a list of IPs with open ports
	Scan(ctx context.Context, targets []string, ports string) ([]HostScanResult, error)
}

// ServiceEnricher defines a contract for deep port analysis (Nmap/Banner Grabbing)
type ServiceEnricher interface {
	// Enrich takes bare host ports and enriches them (versions, banners, CPEs, vulnerabilities)
	Enrich(ctx context.Context, host *HostScanResult) error
}

// ResultRepository is responsible for storing history and retrieving past results
type ResultRepository interface {
	// GetPreviousResult returns history by IP. If there is no data, it returns (_, false, nil)
	GetPreviousResult(ctx context.Context, ip string) (HostScanResult, bool, error)
	// SaveResult saves the current state of the host
	SaveResult(ctx context.Context, result HostScanResult) error
}

// AlertNotifier is responsible for sending notifications about new threats
type AlertNotifier interface {
	// SendDiffAlert sends information about discovered ports/CVEs to the owner
	SendDiffAlert(ctx context.Context, diff ScanDiff) error
}
