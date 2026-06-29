//go:build integration

package tests

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"perimeter-scanner/internal/adapter/masscan"
	"perimeter-scanner/internal/adapter/nmap"
	postgresrepo "perimeter-scanner/internal/adapter/postgres"
	"perimeter-scanner/internal/adapter/vulners"
	"perimeter-scanner/internal/config"
	"perimeter-scanner/internal/domain"
	"perimeter-scanner/internal/usecase"
)

// Logger

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

// Helpers

func newScannerUseCase(t *testing.T, repo *postgresrepo.RepositoryAdapter, notifier domain.AlertNotifier, strategy string) *usecase.ScannerUseCase {
	t.Helper()
	return usecase.NewScannerUseCase(
		masscan.NewScannerAdapter("masscan", 1000, config.GetActiveInterface(), testLogger(t)),
		nmap.NewEnricherAdapter(testLogger(t)),
		&vulners.NoopExploitChecker{},
		repo,
		notifier,
		strategy,
		2,
		testLogger(t),
	)
}

func resolveHost(t *testing.T, hostname string) string {
	t.Helper()
	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		t.Fatalf("failed to resolve %s: %v", hostname, err)
	}
	t.Logf("resolved %s -> %s", hostname, addrs[0])
	return addrs[0]
}

// Notifiers

// noopNotifier discards alerts.
type noopNotifier struct{}

func (n *noopNotifier) SendDiffAlert(_ context.Context, _ domain.ScanDiff) error {
	return nil
}

// capturingNotifier records every ScanDiff that passes through SendDiffAlert.
type capturingNotifier struct {
	alerts []domain.ScanDiff
}

func (n *capturingNotifier) SendDiffAlert(_ context.Context, d domain.ScanDiff) error {
	n.alerts = append(n.alerts, d)
	return nil
}

// TestFullScanPipeline_FindsKnownVulnerableSSH runs the full scan pipeline
// against a pre-started vulnerable SSH container and a real Postgres instance.
// Requires VULN_SSH_HOST and TEST_DATABASE_URL environment variables to be set;
// skips otherwise. Intended to be run via docker-compose.test.yml.
func TestFullScanPipeline_FindsKnownVulnerableSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	targetIP := resolveHost(t, requireEnv(t, "VULN_SSH_HOST"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	suc := newScannerUseCase(t, repo, &noopNotifier{}, config.StrategyAggregated)

	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "22"); err != nil {
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

// TestFullScanPipeline_FirstScan_SendsAlert verifies that scanning a host for
// the first time triggers an alert containing all discovered services.
func TestFullScanPipeline_FirstScan_SendsAlert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	targetIP := resolveHost(t, requireEnv(t, "HTTP_TARGET_HOST"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	notifier := &capturingNotifier{}
	suc := newScannerUseCase(t, repo, notifier, config.StrategyAggregated)

	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "80,443"); err != nil {
		t.Fatalf("scan execution failed: %v", err)
	}

	if len(notifier.alerts) != 1 {
		t.Fatalf("expected exactly 1 alert for first-time scan, got %d", len(notifier.alerts))
	}

	alert := notifier.alerts[0]
	if alert.IP != targetIP {
		t.Errorf("alert IP = %q; want %q", alert.IP, targetIP)
	}
	if len(alert.NewServices) == 0 {
		t.Error("alert should contain at least one new service")
	}

	// Verify the host was actually persisted
	result, found, err := repo.GetPreviousResult(ctx, targetIP)
	if err != nil {
		t.Fatalf("GetPreviousResult: %v", err)
	}
	if !found {
		t.Fatal("host should be persisted after first scan")
	}
	if len(result.Services) == 0 {
		t.Fatal("persisted result should contain services")
	}
}

// TestFullScanPipeline_AggregatedStrategy_OneAlertPerHost verifies that with
// StrategyAggregated a host with multiple open ports produces exactly one alert
// combining all new services, not one per port.
func TestFullScanPipeline_AggregatedStrategy_OneAlertPerHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	targetIP := resolveHost(t, requireEnv(t, "HTTP_TARGET_HOST"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	notifier := &capturingNotifier{}
	suc := newScannerUseCase(t, repo, notifier, config.StrategyAggregated)

	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "80,443"); err != nil {
		t.Fatalf("scan execution failed: %v", err)
	}

	if len(notifier.alerts) != 1 {
		t.Fatalf("aggregated strategy: expected 1 alert for host with 2 ports, got %d", len(notifier.alerts))
	}
	if len(notifier.alerts[0].NewServices) != 2 {
		t.Errorf("expected 2 new services in combined alert, got %d", len(notifier.alerts[0].NewServices))
	}
}

// TestFullScanPipeline_RepeatScan_NoAlert verifies that scanning the same host
// twice without changes does not trigger a second alert.
func TestFullScanPipeline_RepeatScan_NoAlert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	targetIP := resolveHost(t, requireEnv(t, "HTTP_TARGET_HOST"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	notifier := &capturingNotifier{}
	suc := newScannerUseCase(t, repo, notifier, config.StrategyAggregated)

	// First scan — alert expected
	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "80,443"); err != nil {
		t.Fatalf("first scan failed: %v", err)
	}
	if len(notifier.alerts) == 0 {
		t.Fatal("expected alert after first scan")
	}

	alertsBefore := len(notifier.alerts)

	time.Sleep(10 * time.Millisecond)

	// Second scan - identical state, no alert expected
	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "80,443"); err != nil {
		t.Fatalf("second scan failed: %v", err)
	}

	if len(notifier.alerts) != alertsBefore {
		t.Errorf("expected no new alerts on repeat scan, got %d new alert(s)",
			len(notifier.alerts)-alertsBefore)
	}
}

// TestFullScanPipeline_NewPort_SendsAlertWithOnlyNewService verifies that when
// a new port appears between scans, the alert contains only the new service —
// not the ones already known from the previous scan.
func TestFullScanPipeline_NewPort_SendsAlertWithOnlyNewService(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	targetIP := resolveHost(t, requireEnv(t, "HTTP_TARGET_HOST"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	notifier := &capturingNotifier{}
	suc := newScannerUseCase(t, repo, notifier, config.StrategyAggregated)

	// First scan: only port 80
	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "80"); err != nil {
		t.Fatalf("first scan failed: %v", err)
	}
	if len(notifier.alerts) == 0 {
		t.Fatal("expected alert after first scan")
	}

	alertsBefore := len(notifier.alerts)

	time.Sleep(10 * time.Millisecond)

	// Second scan: port 443 now also in scope - simulates a new service appearing
	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "80,443"); err != nil {
		t.Fatalf("second scan failed: %v", err)
	}

	newAlerts := notifier.alerts[alertsBefore:]
	if len(newAlerts) != 1 {
		t.Fatalf("expected 1 alert for new port, got %d", len(newAlerts))
	}

	alert := newAlerts[0]
	for _, svc := range alert.NewServices {
		if svc.Port == 80 {
			t.Error("alert should not contain port 80 - it was already known from the previous scan")
		}
	}

	var found443 bool
	for _, svc := range alert.NewServices {
		if svc.Port == 443 {
			found443 = true
		}
	}
	if !found443 {
		t.Error("alert should contain port 443 as a new service")
	}
}

// TestFullScanPipeline_RepeatScan_ReplacesPreviousResult verifies that after a
// second scan only the latest services are stored — ports absent from the new
// scan do not linger in the database.
func TestFullScanPipeline_RepeatScan_ReplacesPreviousResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	targetIP := resolveHost(t, requireEnv(t, "HTTP_TARGET_HOST"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	suc := newScannerUseCase(t, repo, &noopNotifier{}, config.StrategyAggregated)

	// First scan: both ports
	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "80,443"); err != nil {
		t.Fatalf("first scan failed: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	// Second scan: only port 80 - 443 is now absent
	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "80"); err != nil {
		t.Fatalf("second scan failed: %v", err)
	}

	result, _, err := repo.GetPreviousResult(ctx, targetIP)
	if err != nil {
		t.Fatalf("GetPreviousResult: %v", err)
	}

	for _, svc := range result.Services {
		if svc.Port == 443 {
			t.Error("port 443 should not be present after scan that excluded it")
		}
	}
}

// TestFullScanPipeline_ResultPersisted_ContainsCorrectPorts is a sanity check
// that after scanning http-target on ports 80 and 443 both are retrievable from
// the repository with the correct protocol.
func TestFullScanPipeline_ResultPersisted_ContainsCorrectPorts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	targetIP := resolveHost(t, requireEnv(t, "HTTP_TARGET_HOST"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	suc := newScannerUseCase(t, repo, &noopNotifier{}, config.StrategyAggregated)

	if err := suc.Execute(ctx, []string{targetIP + "/32"}, "80,443"); err != nil {
		t.Fatalf("scan execution failed: %v", err)
	}

	result, found, err := repo.GetPreviousResult(ctx, targetIP)
	if err != nil {
		t.Fatalf("GetPreviousResult: %v", err)
	}
	if !found {
		t.Fatal("expected result to be persisted")
	}

	portSet := make(map[int]string) // port -> proto
	for _, svc := range result.Services {
		portSet[svc.Port] = svc.Proto
	}

	for _, expectedPort := range []int{80, 443} {
		proto, ok := portSet[expectedPort]
		if !ok {
			t.Errorf("expected port %d in results, not found", expectedPort)
			continue
		}
		if proto != "tcp" {
			t.Errorf("port %d: expected proto tcp, got %s", expectedPort, proto)
		}
	}
}
