package nmap

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/Ullaakut/nmap/v4"

	"perimeter-scanner/internal/domain"
)

// EnricherAdapter implements domain.ServiceEnricher using nmap with the vulners script.
// It performs deep service detection (-sV) and CVE lookup for each discovered port.
type EnricherAdapter struct {
	logger *slog.Logger
}

// NewEnricherAdapter constructs an EnricherAdapter.
func NewEnricherAdapter(logger *slog.Logger) *EnricherAdapter {
	return &EnricherAdapter{logger: logger}
}

// Enrich runs nmap against the host's known open ports and populates
// service metadata (version, CPE, banner) and CVE vulnerabilities in place.
// Only ports already present in host.Services are scanned.
func (a *EnricherAdapter) Enrich(ctx context.Context, host *domain.HostScanResult) error {
	if len(host.Services) == 0 {
		return nil
	}

	portsStr := make([]string, len(host.Services))
	for i, svc := range host.Services {
		portsStr[i] = strconv.Itoa(svc.Port)
	}

	a.logger.Debug("Starting Nmap enrichment", "ip", host.IP, "ports", portsStr)

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(host.IP),
		nmap.WithPorts(strings.Join(portsStr, ",")),
		nmap.WithServiceInfo(),      // -sV: version detection
		nmap.WithScripts("vulners"), // CVE lookup via vulners script
	)
	if err != nil {
		return fmt.Errorf("failed to create nmap scanner: %w", err)
	}

	result, err := scanner.Run(ctx)
	if err != nil {
		return fmt.Errorf("nmap execution failed: %w", err)
	}

	if len(result.Hosts) == 0 {
		return nil
	}

	nmapHost := result.Hosts[0]

	var enrichedServices []domain.ServiceInfo

	for _, nmapPort := range nmapHost.Ports {
		if nmapPort.State.State != "open" {
			continue
		}

		svcInfo := domain.ServiceInfo{
			Port:            int(nmapPort.ID),
			Proto:           nmapPort.Protocol,
			Service:         nmapPort.Service.Name,
			Version:         nmapPort.Service.Version,
			Banner:          buildBanner(nmapPort.Service),
			Vulnerabilities: a.parseVulnersScript(nmapPort.Scripts),
		}

		if len(nmapPort.Service.CPEs) > 0 {
			svcInfo.CPE = string(nmapPort.Service.CPEs[0])
		}

		enrichedServices = append(enrichedServices, svcInfo)
	}

	host.Services = enrichedServices
	return nil
}

// parseVulnersScript extracts CVE entries from the vulners nmap script output.
// Non-CVE entries (EDB-ID, PACKETSTORM, MSF, etc.) are intentionally skipped.
func (a *EnricherAdapter) parseVulnersScript(scripts []nmap.Script) []domain.Vulnerability {
	var vulns []domain.Vulnerability

	for _, script := range scripts {
		if script.ID != "vulners" {
			continue
		}

		for _, table := range script.Tables {
			for _, vulnTable := range table.Tables {
				var idVal, typeVal, cvssVal string

				for _, element := range vulnTable.Elements {
					switch element.Key {
					case "id":
						idVal = element.Value
					case "type":
						typeVal = element.Value
					case "cvss":
						cvssVal = element.Value
					}
				}

				// Skip non-CVE identifiers (EDB-ID, PACKETSTORM, MSF, etc.)
				if typeVal != "cve" || idVal == "" {
					continue
				}

				score, _ := strconv.ParseFloat(cvssVal, 64)

				v := domain.Vulnerability{
					CVE:      idVal,
					Score:    score,
					Severity: mapScoreToSeverity(score),
					Link:     fmt.Sprintf("https://vulners.com/cve/%s", idVal),
				}

				vulns = append(vulns, v)
			}
		}
	}

	return vulns
}

// buildBanner assembles a human-readable service description from nmap fields.
func buildBanner(svc nmap.Service) string {
	parts := make([]string, 0, 3)
	if svc.Product != "" {
		parts = append(parts, svc.Product)
	}
	if svc.Version != "" {
		parts = append(parts, svc.Version)
	}
	if svc.ExtraInfo != "" {
		parts = append(parts, svc.ExtraInfo)
	}
	return strings.Join(parts, " ")
}

// mapScoreToSeverity converts a CVSS v3 numeric score to a Severity label
// according to the standard FIRST.org thresholds.
func mapScoreToSeverity(score float64) domain.Severity {
	switch {
	case score >= 9.0:
		return domain.SeverityCritical
	case score >= 7.0:
		return domain.SeverityHigh
	case score >= 4.0:
		return domain.SeverityMedium
	case score >= 0.1:
		return domain.SeverityLow
	default:
		return domain.SeverityInfo
	}
}
