//go:build integration

package integration

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"perimeter-scanner/internal/adapter/masscan"
	"perimeter-scanner/internal/adapter/nmap"
	postgresrepo "perimeter-scanner/internal/adapter/postgres"
	"perimeter-scanner/internal/adapter/vulners"
	"perimeter-scanner/internal/config"
	"perimeter-scanner/internal/domain"
	"perimeter-scanner/internal/usecase"
)

type testLogWriter struct{ t *testing.T }

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(&testLogWriter{t}, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// TestFullScanPipeline_FindsKnownVulnerableSSH runs the full scan pipeline
// against a pre-started vulnerable SSH container and a real Postgres instance.
// Requires VULN_SSH_HOST and TEST_DATABASE_URL environment variables to be set;
// skips otherwise. Intended to be run via docker-compose.test.yml.
func TestFullScanPipeline_FindsKnownVulnerableSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	targetHost := os.Getenv("VULN_SSH_HOST")
	if targetHost == "" {
		t.Skip("VULN_SSH_HOST not set; skipping, run via docker-compose.test.yml")
	}

	addrs, err := net.LookupHost(targetHost)
	if err != nil || len(addrs) == 0 {
		t.Fatalf("failed to resolve %s: %v", targetHost, err)
	}
	targetIP := addrs[0]
	t.Logf("resolved %s -> %s", targetHost, targetIP)

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Fatal("TEST_DATABASE_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("failed to connect to postgres: %v", err)
	}
	defer pool.Close()

	repo, err := postgresrepo.NewDBRepository(ctx, pool)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}

	suc := usecase.NewScannerUseCase(
		masscan.NewScannerAdapter("masscan", 1000, config.GetActiveInterface(), testLogger(t)),
		nmap.NewEnricherAdapter(testLogger(t)),
		&vulners.NoopExploitChecker{},
		repo,
		&noopNotifier{},
		2,
		testLogger(t),
	)

	if err := suc.Execute(ctx, []string{targetIP + "/24"}, "22"); err != nil {
		t.Fatalf("scan execution failed: %v", err)
	}

	result, found, err := repo.GetPreviousResult(ctx, targetIP)
	if err != nil {
		t.Fatalf("failed to fetch scan result: %v", err)
	}
	if !found {
		t.Fatalf("expected a scan result for %s, found none", targetIP)
	}
	if len(result.Services) == 0 {
		t.Fatalf("expected at least one open service, got none")
	}

	expectedCVEs := map[string]float64{
		"CVE-2023-38408": 9.8, "CVE-2026-35414": 8.1, "CVE-2026-35386": 8.1,
		"CVE-2026-35385": 8.1, "CVE-2020-15778": 7.8, "CVE-2016-8858": 7.8,
		"CVE-2016-6515": 7.8, "CVE-2016-10012": 7.8, "CVE-2015-8325": 7.8,
		"CVE-2016-10708": 7.5, "CVE-2016-10009": 7.5, "CVE-2021-41617": 7.0,
		"CVE-2016-10010": 7.0, "CVE-2025-26465": 6.8, "CVE-2019-6110": 6.8,
		"CVE-2019-6109": 6.8, "CVE-2026-35387": 6.5, "CVE-2023-51385": 6.5,
		"CVE-2016-3115": 6.4, "CVE-2016-10011": 6.2, "CVE-2023-48795": 5.9,
		"CVE-2020-14145": 5.9, "CVE-2019-6111": 5.9, "CVE-2018-15473": 5.9,
		"CVE-2016-6210": 5.9, "CVE-2018-20685": 5.3, "CVE-2018-15919": 5.3,
		"CVE-2017-15906": 5.3, "CVE-2016-20012": 5.3, "CVE-2021-36368": 3.7,
		"CVE-2025-61985": 3.6, "CVE-2025-61984": 3.6, "CVE-2026-35388": 2.5,
	}

	var sshPortFound bool
	for _, svc := range result.Services {
		if svc.Port == 22 {
			sshPortFound = true

			if svc.Service != "ssh" {
				t.Errorf("expected service 'ssh', got '%s'", svc.Service)
			}

			expectedVersion := "7.2p2 Ubuntu 4ubuntu2.10"
			if svc.Version != expectedVersion {
				t.Errorf("expected version '%s', got '%s'", expectedVersion, svc.Version)
			}

			expectedBanner := "OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 Ubuntu Linux; protocol 2.0"
			if svc.Banner != expectedBanner {
				t.Errorf("expected banner '%s', got '%s'", expectedBanner, svc.Banner)
			}

			if len(svc.Vulnerabilities) != len(expectedCVEs) {
				t.Errorf("expected exactly %d CVEs, database contains %d", len(expectedCVEs), len(svc.Vulnerabilities))
			}

			for _, v := range svc.Vulnerabilities {
				expectedScore, exists := expectedCVEs[v.CVE]
				if !exists {
					t.Errorf("found unexpected CVE %s in scan results", v.CVE)
					continue
				}
				if v.Score != expectedScore {
					t.Errorf("score mismatch for %s: expected %.1f, got %.1f", v.CVE, expectedScore, v.Score)
				}
			}
		}
	}

	if !sshPortFound {
		t.Fatalf("expected port 22 to be detected, but it wasn't found in results")
	}
}

// noopNotifier discards alerts.
type noopNotifier struct{}

func (n *noopNotifier) SendDiffAlert(_ context.Context, _ domain.ScanDiff) error {
	return nil
}
