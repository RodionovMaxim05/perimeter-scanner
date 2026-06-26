package usecase

import (
	"context"
	"log/slog"
	"strconv"
	"sync"

	"perimeter-scanner/internal/domain"
)

// ScannerUseCase orchestrates the full perimeter scan pipeline:
// fast port discovery -> deep enrichment -> diff with history -> alert.
type ScannerUseCase struct {
	scanner        domain.NetworkScanner
	enricher       domain.ServiceEnricher
	exploitChecker domain.ExploitChecker
	repo           domain.ResultRepository
	notifier       domain.AlertNotifier
	logger         *slog.Logger
	workerCount    int
}

// NewScannerUseCase constructs a ScannerUseCase with all required dependencies.
// workerCount controls how many Nmap enrichment workers run in parallel.
func NewScannerUseCase(
	scanner domain.NetworkScanner,
	enricher domain.ServiceEnricher,
	exploitChecker domain.ExploitChecker,
	repo domain.ResultRepository,
	notifier domain.AlertNotifier,
	logger *slog.Logger,
	workerCount int,
) *ScannerUseCase {
	if workerCount <= 0 {
		workerCount = 1
	}

	return &ScannerUseCase{
		scanner:        scanner,
		enricher:       enricher,
		exploitChecker: exploitChecker,
		repo:           repo,
		notifier:       notifier,
		logger:         logger,
		workerCount:    workerCount,
	}
}

// Execute runs a single full perimeter scan cycle for the given targets and ports.
//
// The pipeline is:
//  1. NetworkScanner — fast discovery of open ports across all targets.
//  2. ServiceEnricher — parallel deep scan of each discovered host.
//  3. Diff — compare current state with the last saved result per host.
//  4. Alert — notify owner if new services or CVEs appeared.
//  5. Persist — save current state to the repository.
//
// Returns a non-nil error if the fast scan fails.
func (suc *ScannerUseCase) Execute(ctx context.Context, targets []string, ports string) error {
	suc.logger.Info("Starting streaming perimeter scan pipeline", "targets", targets, "ports", ports)

	// Initiate background port scanning
	hostsChan, scanErrChan := suc.scanner.Scan(ctx, targets, ports)

	// Enrich results concurrently as they bleed from NetworkScanner
	enrichedChan := suc.startEnrichmentWorkers(ctx, hostsChan)

	for currentHost := range enrichedChan {
		prevHost, found, err := suc.repo.GetPreviousResult(ctx, currentHost.IP)
		if err != nil {
			suc.logger.Error("Failed to get previous result", "ip", currentHost.IP, "error", err)
			continue
		}

		diff := suc.calculateDiff(currentHost, prevHost, found)

		if len(diff.NewServices) > 0 {
			suc.logger.Warn("New services or vulnerabilities detected", "ip", diff.IP, "new_services", len(diff.NewServices))
			if err := suc.notifier.SendDiffAlert(ctx, diff); err != nil {
				suc.logger.Error("Failed to send alert", "ip", diff.IP, "error", err)
			}
		}

		if err := suc.repo.SaveResult(ctx, currentHost); err != nil {
			suc.logger.Error("Failed to save host state", "ip", currentHost.IP, "error", err)
		}
	}

	if err := <-scanErrChan; err != nil {
		suc.logger.Error("Masscan pipeline finished with error", "error", err)
		return err
	}

	suc.logger.Info("Perimeter scan iteration finished successfully")
	return nil
}

// startEnrichmentWorkers initializes a concurrent worker pool to process service enrichment.
//
// It spawns a fixed number of goroutines that compete for raw host results on the input channel,
// performs banner grabbing and exploit status mapping, and aggregates outcomes into a single output channel.
func (suc *ScannerUseCase) startEnrichmentWorkers(ctx context.Context, inChan <-chan domain.HostScanResult) <-chan domain.HostScanResult {
	outChan := make(chan domain.HostScanResult)
	var wg sync.WaitGroup

	for i := 0; i < suc.workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for host := range inChan {
				select {
				case <-ctx.Done():
					suc.logger.Warn("Worker cancelled", "worker_id", workerID)
					return
				default:
				}

				suc.logger.Debug("Worker processing host", "worker_id", workerID, "ip", host.IP)

				if err := suc.enricher.Enrich(ctx, &host); err != nil {
					suc.logger.Error("Enrichment failed for host", "ip", host.IP, "error", err)
				}

				suc.enrichExploitsBatch(ctx, &host)

				select {
				case <-ctx.Done():
					return
				case outChan <- host:
				}
			}
		}(i)
	}

	// Wait for all workers
	go func() {
		wg.Wait()
		close(outChan)
	}()

	return outChan
}

// enrichExploitsBatch queries the exploit checker service in a single batch request
// for all unique CVEs identified on the host, updating their exploit availability status.
func (suc *ScannerUseCase) enrichExploitsBatch(ctx context.Context, host *domain.HostScanResult) {
	cveSet := make(map[string]struct{})
	for _, svc := range host.Services {
		for _, vuln := range svc.Vulnerabilities {
			cveSet[vuln.CVE] = struct{}{}
		}
	}

	if len(cveSet) == 0 {
		return
	}

	cveIDs := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		cveIDs = append(cveIDs, cve)
	}

	exploitMap, err := suc.exploitChecker.CheckExploits(ctx, cveIDs)
	if err != nil {
		suc.logger.Error("Failed to check exploit status in batch", "cve_count", len(cveIDs), "error", err)
		return
	}

	for sIdx := range host.Services {
		for vIdx := range host.Services[sIdx].Vulnerabilities {
			cve := host.Services[sIdx].Vulnerabilities[vIdx].CVE
			host.Services[sIdx].Vulnerabilities[vIdx].ExploitAvailable = exploitMap[cve]
		}
	}
}

// calculateDiff compares the current host scan result against the previous one.
//
// If the host has never been seen before (found == false), all current services
// are treated as new. Otherwise only services whose port/proto pair did not exist
// in the previous scan, and services that have new CVEs, are included in the diff.
func (suc *ScannerUseCase) calculateDiff(current, previous domain.HostScanResult, found bool) domain.ScanDiff {
	diff := domain.ScanDiff{
		IP:          current.IP,
		ScanTime:    current.ScanTime,
		NewServices: []domain.ServiceInfo{},
	}

	if !found {
		diff.NewServices = current.Services
		return diff
	}

	prevServicesMap := make(map[string]domain.ServiceInfo)
	for _, oldService := range previous.Services {
		key := makeServiceKey(oldService.Port, oldService.Proto)
		prevServicesMap[key] = oldService
	}

	for _, curService := range current.Services {
		key := makeServiceKey(curService.Port, curService.Proto)
		oldService, exists := prevServicesMap[key]
		if !exists {
			// Completely new port - report the full service including its CVEs
			diff.NewServices = append(diff.NewServices, curService)
			continue
		}

		// Port already known - check if new CVEs appeared on it
		newCVEs := suc.findNewVulnerabilities(curService.Vulnerabilities, oldService.Vulnerabilities)
		if len(newCVEs) > 0 {
			// Include only the new CVEs so the owner is not spammed with known issues
			serviceWithNewCVEs := curService
			serviceWithNewCVEs.Vulnerabilities = newCVEs
			diff.NewServices = append(diff.NewServices, serviceWithNewCVEs)
		}
	}

	return diff
}

// makeServiceKey returns a string key for a port/protocol pair,
// e.g. "443/tcp". Used to index services in diff maps.
func makeServiceKey(port int, proto string) string {
	return strconv.Itoa(port) + "/" + proto
}

// findNewVulnerabilities returns CVEs that appear in current but not in previous.
// Comparison is done by CVE identifier.
func (suc *ScannerUseCase) findNewVulnerabilities(current, previous []domain.Vulnerability) []domain.Vulnerability {
	if len(previous) == 0 {
		return current
	}

	prevVulsMap := make(map[string]struct{})
	for _, v := range previous {
		prevVulsMap[v.CVE] = struct{}{}
	}

	var newVuls []domain.Vulnerability
	for _, v := range current {
		if _, seen := prevVulsMap[v.CVE]; !seen {
			newVuls = append(newVuls, v)
		}

	}

	return newVuls
}
