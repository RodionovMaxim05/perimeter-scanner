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

// masscanPort represents a single port entry in masscan's JSON output.

type masscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

// masscanResult represents a single host entry in masscan's JSON output.
type masscanResult struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

// ScannerAdapter wraps masscan as an external process and streams discovered
// hosts over a channel as JSON records arrive on stdout, without waiting for
// the full scan to complete.
type ScannerAdapter struct {
	binaryPath string // path to the masscan binary, or "masscan" if resolved via PATH
	rate       int    // packet transmission rate (packets per second)
	iface      string // network interface to bind to; empty means masscan picks the default
	logger     *slog.Logger
}

// NewScannerAdapter constructs a ScannerAdapter.
func NewScannerAdapter(binaryPath string, rate int, iface string, logger *slog.Logger) *ScannerAdapter {
	logger.Info("initializing masscan adapter",
		"binaryPath", binaryPath,
		"rate", rate,
		"interface", iface,
	)

	return &ScannerAdapter{
		binaryPath: binaryPath,
		rate:       rate,
		iface:      iface,
		logger:     logger,
	}
}

// Scan launches masscan via stdbuf (to disable output buffering) and streams
// discovered hosts as they are found, without waiting for the scan to finish.
//
// targets is a list of CIDRs or individual IPs (e.g. ["192.168.1.0/24", "10.0.0.1"]).
// ports is a masscan-format port specification (e.g. "22,80,443,8000-9000").
//
// Returns two channels:
//   - hostsChan: emits one [domain.HostScanResult] per discovered host; closed when the scan ends.
//   - errChan:   buffered (cap 1); receives at most one fatal error, then is closed.
//
// The caller must drain hostsChan until it is closed, even if errChan fires,
// to avoid blocking the internal goroutine. Cancelling ctx terminates masscan
// and causes both channels to be closed without an error.
func (sa *ScannerAdapter) Scan(ctx context.Context, targets []string, ports string) (<-chan domain.HostScanResult, <-chan error) {
	hostsChan := make(chan domain.HostScanResult)
	errChan := make(chan error, 1)

	if len(targets) == 0 {
		close(hostsChan)
		close(errChan)
		return hostsChan, errChan
	}

	go func() {
		defer close(hostsChan)
		defer close(errChan)

		args := []string{
			"-oL", sa.binaryPath,
			"-p", ports,
			"--rate", strconv.Itoa(sa.rate),
			"-oJ", "-",
			"--interface", sa.iface,
		}
		args = append(args, targets...)

		cmd := exec.CommandContext(ctx, "stdbuf", args...)

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			errChan <- fmt.Errorf("failed to create stdout pipe: %w", err)
			return
		}

		var stderrBuf bytes.Buffer
		cmd.Stderr = &stderrBuf

		startTime := time.Now()
		if err := cmd.Start(); err != nil {
			errChan <- fmt.Errorf("failed to start masscan: %w", err)
			return
		}

		dec := json.NewDecoder(stdout)

		// Read the opening bracket `[`
		t, err := dec.Token()
		if err != nil {
			waitErr := cmd.Wait()
			if ctx.Err() != nil {
				// Scan cancelled by user
				return
			}
			if waitErr != nil {
				errChan <- fmt.Errorf("masscan failed on startup: %w (stderr: %s)", waitErr, stderrBuf.String())
			} else {
				sa.logger.Debug("Masscan returned no output")
			}
			return
		}

		if delim, ok := t.(json.Delim); !ok || delim != '[' {
			_ = cmd.Wait()
			errChan <- fmt.Errorf("expected json array start '[', got %v", t)
			return
		}

		hostCount := 0

		// Read the array elements one by one as they appear in stdout
		for dec.More() {
			var r masscanResult
			if err := dec.Decode(&r); err != nil {
				_ = cmd.Wait()
				if ctx.Err() != nil {
					// Error was caused by context cancellation
					return
				}
				errChan <- fmt.Errorf("failed to decode masscan item: %w", err)
				return
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

			hostResult := domain.HostScanResult{
				IP:       r.IP,
				ScanTime: startTime,
				Services: services,
			}

			// Send the host to the channel
			select {
			case <-ctx.Done():
				_ = cmd.Wait()
				return
			case hostsChan <- hostResult:
				hostCount++
			}
		}

		// Read the closing bracket `]`
		_, _ = dec.Token()

		// Waiting the final completion of the process
		if err := cmd.Wait(); err != nil {
			if ctx.Err() != nil {
				return
			}
			errChan <- fmt.Errorf("masscan finished with error: %w (stderr: %s)", err, stderrBuf.String())
			return
		}

		sa.logger.Debug("Masscan streaming finished", "duration", time.Since(startTime), "found_hosts", hostCount)
	}()

	return hostsChan, errChan
}
