package masscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"time"

	"perimeter-scanner/internal/domain"
)

type masscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

type masscanResult struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

// ScannerAdapter runs masscan as an external process and parses its JSON output.
type ScannerAdapter struct {
	binaryPath string
	rate       int
	iface      string
	logger     *slog.Logger
}

// NewScannerAdapter constructs a ScannerAdapter.
// If binaryPath is empty, "masscan" is looked up in PATH.
func NewScannerAdapter(binaryPath string, rate int, iface string, logger *slog.Logger) *ScannerAdapter {
	if binaryPath == "" {
		binaryPath = "masscan"
	}
	return &ScannerAdapter{
		binaryPath: binaryPath,
		rate:       rate,
		iface:      iface,
		logger:     logger,
	}
}

// Scan runs masscan against the given targets and ports and returns discovered hosts.
// Targets are CIDRs or individual IPs; ports is a masscan-format string e.g. "22,80,443,8000-9000".
// Returns (nil, nil) if masscan finds no open ports.
func (sa *ScannerAdapter) Scan(ctx context.Context, targets []string, ports string) ([]domain.HostScanResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{
		"-p", ports,
		"--rate", strconv.Itoa(sa.rate),
		"-oJ", "-",
	}
	if sa.iface != "" {
		args = append(args, "--interface", sa.iface)
	}
	args = append(args, targets...)

	cmd := exec.CommandContext(ctx, sa.binaryPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start masscan: %w", err)
	}

	results := make([]domain.HostScanResult, 0)

	dec := json.NewDecoder(stdout)

	// Read the opening bracket `[`
	t, err := dec.Token()
	if err != nil {
		// Masscan found nothing
		_ = cmd.Wait()
		sa.logger.Debug("Masscan returned no output")
		return nil, nil
	}

	if delim, ok := t.(json.Delim); !ok || delim != '[' {
		_ = cmd.Wait()
		return nil, fmt.Errorf("expected json array start '[', got %v", t)
	}

	// Read the array elements one by one until there is data
	for dec.More() {
		var r masscanResult
		if err := dec.Decode(&r); err != nil {
			_ = cmd.Wait()
			return nil, fmt.Errorf("failed to decode masscan item: %w", err)
		}

		if r.IP == "" || len(r.Ports) == 0 {
			continue
		}

		services := make([]domain.ServiceInfo, 0, len(r.Ports))
		for _, p := range r.Ports {
			if p.Status != "open" {
				continue
			}

			services = append(services, domain.ServiceInfo{
				Port:  p.Port,
				Proto: p.Proto,
			})
		}

		results = append(results, domain.HostScanResult{
			IP:       r.IP,
			ScanTime: startTime,
			Services: services,
		})
	}

	// Read the closing bracket `]`
	_, _ = dec.Token()

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("masscan finished with error: %w (stderr: %s)", err, stderrBuf.String())
	}

	sa.logger.Debug("Masscan streaming finished", "duration", time.Since(startTime), "found_hosts", len(results))
	return results, nil
}
