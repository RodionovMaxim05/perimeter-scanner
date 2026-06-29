package usecase

import (
	"context"
	"log/slog"
	"strconv"
	"sync"

	"perimeter-scanner/internal/config"
	"perimeter-scanner/internal/domain"
)

// ScannerUseCase orchestrates the full perimeter scan pipeline:
//
//	Port discovery -> Service enrichment -> CVE lookup
//	-> Exploit check -> Diff with history -> Alert -> Persist
//
// All stages are pipelined and streaming: enrichment workers start processing
// hosts as soon as the scanner emits them, without waiting for the full scan to finish.
type ScannerUseCase struct {
	scanner               domain.NetworkScanner   // fast port discovery
	enricher              domain.ServiceEnricher  // deep service fingerprinting and CVE lookup
	exploitChecker        domain.ExploitChecker   // exploit availability lookup
	repo                  domain.ResultRepository // persistence layer
	notifier              domain.AlertNotifier    // alert delivery
	notification_strategy string                  // config.StrategyImmediate or config.StrategyAggregated
	workerCount           int                     // number of parallel enrichment workers
	logger                *slog.Logger
}

// NewScannerUseCase constructs a ScannerUseCase with all required dependencies.
// workerCount controls how many Nmap enrichment workers run in parallel.
// notification_strategy must be one of the constants defined in the config package.
func NewScannerUseCase(
	scanner domain.NetworkScanner,
	enricher domain.ServiceEnricher,
	exploitChecker domain.ExploitChecker,
	repo domain.ResultRepository,
	notifier domain.AlertNotifier,
	notification_strategy string,
	workerCount int,
	logger *slog.Logger,
) *ScannerUseCase {
	if workerCount <= 0 {
		workerCount = 1
	}

	return &ScannerUseCase{
		scanner:               scanner,
		enricher:              enricher,
		exploitChecker:        exploitChecker,
		repo:                  repo,
		notifier:              notifier,
		notification_strategy: notification_strategy,
		workerCount:           workerCount,
		logger:                logger,
	}
}

// Execute runs a single full perimeter scan cycle for the given targets and ports.
//
// The pipeline stages are:
//  1. NetworkScanner  — streams discovered open ports as hosts are found.
//  2. ServiceEnricher — parallel service fingerprinting and CVE lookup per host.
//  3. ExploitChecker  — batch exploit availability check for all CVEs on a host.
//  4. Aggregation     — ports emitted separately by the scanner are merged into
//     a single HostScanResult per IP before persistence and diff.
//  5. Diff            — compare against the last persisted state for the same IP.
//  6. AlertNotifier   — notify according to the configured notification strategy.
//  7. Repository      — persist the aggregated state, replacing the previous record.
//
// Stages 1–3 are fully pipelined: enrichment starts as soon as the first host
// arrives from the scanner, without waiting for the full scan to complete.
//
// Notification timing depends on notification_strategy:
//   - Immediate:  diff and alert happen in stage 3, before aggregation is complete.
//     Each enriched port result is diffed independently against the stored state,
//     so a host with multiple new ports may trigger multiple alerts.
//   - Aggregated: diff and alert happen in stage 5, after all ports for a host
//     are collected. A host with multiple new ports produces one combined alert.
//
// Returns a non-nil error only if the underlying scanner fails fatally.
// Per-host enrichment, alert, and persistence errors are logged and skipped
// so a single bad host does not abort the entire cycle.
func (suc *ScannerUseCase) Execute(ctx context.Context, targets []string, ports string) error {
	suc.logger.Info("Starting streaming perimeter scan pipeline", "targets", targets, "ports", ports)

	// Initiate background port scanning
	hostsChan, scanErrChan := suc.scanner.Scan(ctx, targets, ports)

	// Enrich results concurrently as they bleed from NetworkScanner
	enrichedChan := suc.startEnrichmentWorkers(ctx, hostsChan)

	// Aggregate per-port results into per-host results
	aggregatedHosts := make(map[string]domain.HostScanResult)

	for currentHost := range enrichedChan {
		if suc.notification_strategy == config.StrategyImmediate {
			prevHost, found, err := suc.repo.GetPreviousResult(ctx, currentHost.IP)
			if err != nil {
				suc.logger.Error("Failed to get previous result for immediate check", "ip", currentHost.IP, "error", err)
			}

			diff := suc.calculateDiff(currentHost, prevHost, found)
			if len(diff.NewServices) > 0 {
				suc.logger.Warn("Immediate alert: New services or vulnerabilities detected", "ip", diff.IP)
				if err := suc.notifier.SendDiffAlert(ctx, diff); err != nil {
					suc.logger.Error("Failed to send alert", "ip", diff.IP, "error", err)
				}
			}
		}

		host, exists := aggregatedHosts[currentHost.IP]
		if !exists {
			aggregatedHosts[currentHost.IP] = currentHost
			continue
		}
		host.Services = append(host.Services, currentHost.Services...)
		aggregatedHosts[currentHost.IP] = host
	}

	// Process each fully aggregated host: alert (if aggregated strategy) and persist.
	for _, finalHost := range aggregatedHosts {
		if suc.notification_strategy == config.StrategyAggregated {
			prevHost, found, err := suc.repo.GetPreviousResult(ctx, finalHost.IP)
			if err != nil {
				suc.logger.Error("Failed to get previous result for aggregated check", "ip", finalHost.IP, "error", err)
				continue
			}

			diff := suc.calculateDiff(finalHost, prevHost, found)
			if len(diff.NewServices) > 0 {
				suc.logger.Warn("Aggregated alert: New services or vulnerabilities detected", "ip", diff.IP)
				if err := suc.notifier.SendDiffAlert(ctx, diff); err != nil {
					suc.logger.Error("Failed to send alert", "ip", diff.IP, "error", err)
				}
			}
		}

		if err := suc.repo.SaveResult(ctx, finalHost); err != nil {
			suc.logger.Error("Failed to save final host state", "ip", finalHost.IP, "error", err)
		}
	}

	if err := <-scanErrChan; err != nil {
		suc.logger.Error("Masscan pipeline finished with error", "error", err)
		return err
	}

	suc.logger.Info("Perimeter scan iteration finished successfully")
	return nil
}

// startEnrichmentWorkers starts a pool of workerCount goroutines that consume
// raw hosts from inChan, enrich each host with service fingerprints and exploit
// data, and forward results to the returned channel.
//
// The output channel is closed automatically once all workers finish, which
// happens after inChan is closed and drained. If ctx is cancelled, each worker
// stops after completing its current host (no mid-host cancellation).
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

// findNewVulnerabilities returns vulnerabilities from current that are considered
// new or escalated compared to previous. A vulnerability is included if:
//   - its CVE ID was not present in the previous scan at all, or
//   - it was known before but now has a public exploit that wasn't recorded then.
func (suc *ScannerUseCase) findNewVulnerabilities(current, previous []domain.Vulnerability) []domain.Vulnerability {
	if len(previous) == 0 {
		return current
	}

	prevVulsMap := make(map[string]domain.Vulnerability)
	for _, v := range previous {
		prevVulsMap[v.CVE] = v
	}

	var newVuls []domain.Vulnerability
	for _, v := range current {
		_, knownCVE := prevVulsMap[v.CVE]
		if !knownCVE {
			// CVE not seen before — report regardless of exploit status
			newVuls = append(newVuls, v)
			continue
		}
		if v.ExploitAvailable && !prevVulsMap[v.CVE].ExploitAvailable {
			// Known CVE that has escalated: exploit became publicly available.
			newVuls = append(newVuls, v)
		}
	}

	return newVuls
}
