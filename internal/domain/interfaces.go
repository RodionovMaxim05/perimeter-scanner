package domain

import "context"

// NetworkScanner defines a contract for the primary fast scan.
type NetworkScanner interface {
	// Scan triggers an asynchronous scan over targets and ports.
	// It streams discovered hosts through a results channel and emits any terminal
	// execution error via an error channel.
	Scan(ctx context.Context, targets []string, ports string) (<-chan HostScanResult, <-chan error)
}

// ServiceEnricher defines a contract for deep port analysis.
type ServiceEnricher interface {
	// Enrich takes bare host ports and enriches them (versions, banners, CPEs, vulnerabilities).
	Enrich(ctx context.Context, host *HostScanResult) error
}

// ExploitChecker defines a contract for checking public exploit availability for a CVE.
type ExploitChecker interface {
	// CheckExploits reports exploit availability for a batch of CVE IDs at once.
	// The returned map contains an entry for every CVE that was found.
	CheckExploits(ctx context.Context, cveIDs []string) (map[string]bool, error)
}

// ResultRepository is responsible for storing history and retrieving past results.
type ResultRepository interface {
	// GetPreviousResult returns history by IP. If there is no data, it returns (_, false, nil).
	GetPreviousResult(ctx context.Context, ip string) (HostScanResult, bool, error)
	// SaveResult saves the current state of the host.
	SaveResult(ctx context.Context, result HostScanResult) error
}

// AlertNotifier is responsible for sending notifications about new threats.
type AlertNotifier interface {
	// SendDiffAlert sends information about discovered ports/CVEs to the owner.
	SendDiffAlert(ctx context.Context, diff ScanDiff) error
}
