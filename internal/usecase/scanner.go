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
	scanner     domain.NetworkScanner
	enricher    domain.ServiceEnricher
	repo        domain.ResultRepository
	notifier    domain.AlertNotifier
	logger      *slog.Logger
	workerCount int
}

// NewScannerUseCase constructs a ScannerUseCase with all required dependencies.
// workerCount controls how many Nmap enrichment workers run in parallel.
func NewScannerUseCase(
	scanner domain.NetworkScanner,
	enricher domain.ServiceEnricher,
	repo domain.ResultRepository,
	notifier domain.AlertNotifier,
	logger *slog.Logger,
	workerCount int,
) *ScannerUseCase {
	if workerCount <= 0 {
		workerCount = 1
	}

	return &ScannerUseCase{
		scanner:     scanner,
		enricher:    enricher,
		repo:        repo,
		notifier:    notifier,
		logger:      logger,
		workerCount: workerCount,
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
	suc.logger.Info("Starting perimeter scan", "targets", targets, "ports", ports)

	rawHosts, err := suc.scanner.Scan(ctx, targets, ports)
	if err != nil {
		suc.logger.Error("Fast scan failed", "error", err)
		return err
	}

	if len(rawHosts) == 0 {
		suc.logger.Info("No open ports found on the perimeter")
		return nil
	}

	enrichedHosts := suc.enrichHostsParallel(ctx, rawHosts)

	for _, currentHost := range enrichedHosts {
		prevHost, found, err := suc.repo.GetPreviousResult(ctx, currentHost.IP)
		if err != nil {
			suc.logger.Error("Failed to get previous result", "ip", currentHost.IP, "error", err)
			continue
		}

		diff := suc.calculateDiff(currentHost, prevHost, found)

		if len(diff.NewServices) > 0 {
			suc.logger.Warn("New services or vulnerabilities detected",
				"ip", diff.IP,
				"new_services", len(diff.NewServices),
			)
			if err := suc.notifier.SendDiffAlert(ctx, diff); err != nil {
				suc.logger.Error("Failed to send alert", "ip", diff.IP, "error", err)
			}
		}

		if err := suc.repo.SaveResult(ctx, currentHost); err != nil {
			suc.logger.Error("Failed to save host state", "ip", currentHost.IP, "error", err)
		}
	}

	suc.logger.Info("Perimeter scan iteration finished successfully")
	return nil
}

// enrichHostsParallel runs enrichment concurrently using a worker pool.
//
// It spawns workerCount goroutines, each pulling enrichment jobs from a buffered channel.
// If ctx is cancelled, workers stop before processing the next host.
// Hosts that fail enrichment are still included in the result with whatever
// data was populated before the error.
func (suc *ScannerUseCase) enrichHostsParallel(ctx context.Context, hosts []domain.HostScanResult) []domain.HostScanResult {
	numJobs := len(hosts)
	jobsChan := make(chan domain.HostScanResult, numJobs)
	resultsChan := make(chan domain.HostScanResult, numJobs)

	// Filling the channel with tasks
	for _, host := range hosts {
		jobsChan <- host
	}
	close(jobsChan)

	var wg sync.WaitGroup

	for i := 0; i < suc.workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for host := range jobsChan {
				select {
				case <-ctx.Done():
					suc.logger.Warn("Worker cancelled", "worker_id", workerID)
					return
				default:
				}

				suc.logger.Debug("Worker processing host", "worker_id", workerID, "ip", host.IP)

				err := suc.enricher.Enrich(ctx, &host)
				if err != nil {
					suc.logger.Error("Enrichment failed for host", "ip", host.IP, "error", err)
				}
				resultsChan <- host
			}
		}(i)
	}

	// Wait for all workers
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collecting results from channel
	var enrichedHosts []domain.HostScanResult
	for res := range resultsChan {
		enrichedHosts = append(enrichedHosts, res)
	}

	return enrichedHosts
}

// calculateDiff compares the current host scan result against the previous one.
//
// If the host has never been seen before (found == false), all current services
// are treated as new. Otherwise only services whose port/proto pair did not exist
// in the previous scan, and services that have new CVEs, are included in the diff.
func (suc *ScannerUseCase) calculateDiff(current, previous domain.HostScanResult, found bool) domain.ScanDiff {
	diff := domain.ScanDiff{
		IP:          current.IP,
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
