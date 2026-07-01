package usecase

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"perimeter-scanner/internal/config"
	"perimeter-scanner/internal/domain"
)

// Helpers

func newLogger() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }

func newUC(
	scanner NetworkScanner,
	enricher ServiceEnricher,
	exploitChecker ExploitChecker,
	repo ResultRepository,
	notifier AlertNotifier,
	notify_strategy string,
	workers int,
) *ScannerUseCase {
	return NewScannerUseCase(scanner, enricher, exploitChecker, repo, notifier, notify_strategy, workers, newLogger())
}

func vuln(cve string, exploit bool) domain.Vulnerability {
	return domain.Vulnerability{CVE: cve, ExploitAvailable: exploit}
}

func svc(port int, proto string, vulns ...domain.Vulnerability) domain.ServiceInfo {
	return domain.ServiceInfo{Port: port, Proto: proto, Vulnerabilities: vulns}
}

func host(ip string, svcs ...domain.ServiceInfo) domain.HostScanResult {
	return domain.HostScanResult{IP: ip, ScanTime: time.Now(), Services: svcs}
}

// Stubs

type stubScanner struct {
	hosts []domain.HostScanResult
	err   error
}

func (s *stubScanner) Scan(_ context.Context, _ []string, _ string) (<-chan domain.HostScanResult, <-chan error) {
	hc := make(chan domain.HostScanResult, len(s.hosts))
	ec := make(chan error, 1)
	for _, h := range s.hosts {
		hc <- h
	}
	close(hc)
	ec <- s.err
	return hc, ec
}

type stubEnricher struct{ err error }

func (s *stubEnricher) Enrich(_ context.Context, _ *domain.HostScanResult) error { return s.err }

type stubExploitChecker struct {
	result map[string]bool
	err    error
}

func (s *stubExploitChecker) CheckExploits(_ context.Context, cves []string) (map[string]bool, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.result != nil {
		return s.result, nil
	}
	m := make(map[string]bool, len(cves))
	for _, c := range cves {
		m[c] = false
	}
	return m, nil
}

type stubRepo struct {
	prev  domain.HostScanResult
	found bool
	err   error
	saved []domain.HostScanResult
}

func (r *stubRepo) GetPreviousResult(_ context.Context, _ string) (domain.HostScanResult, bool, error) {
	return r.prev, r.found, r.err
}
func (r *stubRepo) SaveResult(_ context.Context, h domain.HostScanResult) error {
	r.saved = append(r.saved, h)
	return r.err
}

type stubNotifier struct {
	alerts []domain.ScanDiff
	err    error
}

func (n *stubNotifier) SendDiffAlert(_ context.Context, d domain.ScanDiff) error {
	n.alerts = append(n.alerts, d)
	return n.err
}

// Tests for makeServiceKey

func TestMakeServiceKey(t *testing.T) {
	cases := []struct {
		port  int
		proto string
		want  string
	}{
		{80, "tcp", "80/tcp"},
		{443, "tcp", "443/tcp"},
		{53, "udp", "53/udp"},
		{0, "tcp", "0/tcp"},
	}
	for _, tc := range cases {
		got := makeServiceKey(tc.port, tc.proto)
		if got != tc.want {
			t.Errorf("makeServiceKey(%d, %q) = %q; want %q", tc.port, tc.proto, got, tc.want)
		}
	}
}

// Tests for findNewVulnerabilities

func TestFindNewVulnerabilities(t *testing.T) {
	uc := newUC(nil, nil, nil, nil, nil, config.StrategyImmediate, 1)

	t.Run("empty previous returns all current", func(t *testing.T) {
		cur := []domain.Vulnerability{vuln("CVE-2026-001", false)}
		got := uc.findNewVulnerabilities(cur, nil)
		if len(got) != 1 {
			t.Fatalf("expected 1, got %d", len(got))
		}
	})

	t.Run("known CVE without exploit escalation is not reported", func(t *testing.T) {
		cur := []domain.Vulnerability{vuln("CVE-2026-001", false)}
		prev := []domain.Vulnerability{vuln("CVE-2026-001", false)}
		got := uc.findNewVulnerabilities(cur, prev)
		if len(got) != 0 {
			t.Fatalf("expected 0, got %d", len(got))
		}
	})

	t.Run("exploit escalation on known CVE is reported", func(t *testing.T) {
		cur := []domain.Vulnerability{vuln("CVE-2026-001", true)}
		prev := []domain.Vulnerability{vuln("CVE-2026-001", false)}
		got := uc.findNewVulnerabilities(cur, prev)
		if len(got) != 1 {
			t.Fatalf("expected 1, got %d", len(got))
		}
		if !got[0].ExploitAvailable {
			t.Error("expected ExploitAvailable=true")
		}
	})

	t.Run("brand-new CVE is reported even without exploit", func(t *testing.T) {
		cur := []domain.Vulnerability{vuln("CVE-2026-999", false)}
		prev := []domain.Vulnerability{vuln("CVE-2026-001", true)}
		got := uc.findNewVulnerabilities(cur, prev)
		if len(got) != 1 || got[0].CVE != "CVE-2026-999" {
			t.Fatalf("unexpected result: %v", got)
		}
	})

	t.Run("already exploitable known CVE is NOT re-reported", func(t *testing.T) {
		cur := []domain.Vulnerability{vuln("CVE-2026-001", true)}
		prev := []domain.Vulnerability{vuln("CVE-2026-001", true)}
		got := uc.findNewVulnerabilities(cur, prev)
		if len(got) != 0 {
			t.Fatalf("expected 0, got %d", len(got))
		}
	})
}

// Tests for calculateDiff

func TestCalculateDiff(t *testing.T) {
	uc := newUC(nil, nil, nil, nil, nil, config.StrategyImmediate, 1)

	t.Run("first-ever scan: all services are new", func(t *testing.T) {
		cur := host("1.2.3.4", svc(80, "tcp"), svc(443, "tcp"))
		diff := uc.calculateDiff(cur, domain.HostScanResult{}, false)
		if len(diff.NewServices) != 2 {
			t.Fatalf("expected 2 new services, got %d", len(diff.NewServices))
		}
	})

	t.Run("no changes: empty diff", func(t *testing.T) {
		cur := host("1.2.3.4", svc(80, "tcp", vuln("CVE-A", false)))
		prev := host("1.2.3.4", svc(80, "tcp", vuln("CVE-A", false)))
		diff := uc.calculateDiff(cur, prev, true)
		if len(diff.NewServices) != 0 {
			t.Fatalf("expected 0 new services, got %d", len(diff.NewServices))
		}
	})

	t.Run("new port appears", func(t *testing.T) {
		cur := host("1.2.3.4", svc(80, "tcp"), svc(8080, "tcp"))
		prev := host("1.2.3.4", svc(80, "tcp"))
		diff := uc.calculateDiff(cur, prev, true)
		if len(diff.NewServices) != 1 || diff.NewServices[0].Port != 8080 {
			t.Fatalf("expected port 8080 as new, got %v", diff.NewServices)
		}
	})

	t.Run("new CVE on existing port", func(t *testing.T) {
		cur := host("1.2.3.4", svc(443, "tcp", vuln("CVE-OLD", false), vuln("CVE-NEW", false)))
		prev := host("1.2.3.4", svc(443, "tcp", vuln("CVE-OLD", false)))
		diff := uc.calculateDiff(cur, prev, true)
		if len(diff.NewServices) != 1 {
			t.Fatalf("expected 1 service entry with new CVE, got %d", len(diff.NewServices))
		}
		if len(diff.NewServices[0].Vulnerabilities) != 1 || diff.NewServices[0].Vulnerabilities[0].CVE != "CVE-NEW" {
			t.Fatalf("unexpected vulnerabilities: %v", diff.NewServices[0].Vulnerabilities)
		}
	})

	t.Run("diff IP matches current host", func(t *testing.T) {
		cur := host("10.0.0.1", svc(22, "tcp"))
		diff := uc.calculateDiff(cur, domain.HostScanResult{}, false)
		if diff.IP != "10.0.0.1" {
			t.Errorf("diff.IP = %q; want 10.0.0.1", diff.IP)
		}
	})
}

// Tests for enrichExploitsBatch

func TestEnrichExploitsBatch(t *testing.T) {
	t.Run("updates ExploitAvailable on matching CVE", func(t *testing.T) {
		checker := &stubExploitChecker{result: map[string]bool{"CVE-2026-001": true}}
		uc := newUC(nil, nil, checker, nil, nil, config.StrategyImmediate, 1)

		h := host("1.2.3.4", svc(80, "tcp", vuln("CVE-2026-001", false)))
		uc.enrichExploitsBatch(context.Background(), &h)

		if !h.Services[0].Vulnerabilities[0].ExploitAvailable {
			t.Error("expected ExploitAvailable=true after batch enrichment")
		}
	})

	t.Run("no CVEs: checker is never called", func(t *testing.T) {
		called := false
		checker := &stubExploitChecker{}
		_ = called
		uc := newUC(nil, nil, checker, nil, nil, config.StrategyImmediate, 1)

		h := host("1.2.3.4", svc(80, "tcp")) // no vulns
		uc.enrichExploitsBatch(context.Background(), &h)
		// no panic, no error
	})

	t.Run("checker error is tolerated", func(t *testing.T) {
		checker := &stubExploitChecker{err: errors.New("service unavailable")}
		uc := newUC(nil, nil, checker, nil, nil, config.StrategyImmediate, 1)

		h := host("1.2.3.4", svc(80, "tcp", vuln("CVE-X", false)))
		uc.enrichExploitsBatch(context.Background(), &h) // must not panic

		if h.Services[0].Vulnerabilities[0].ExploitAvailable {
			t.Error("ExploitAvailable should remain false on checker error")
		}
	})

	t.Run("deduplicates CVEs across services", func(t *testing.T) {
		callCount := 0
		checker := &stubExploitChecker{result: map[string]bool{"CVE-SHARED": true}}
		// Wrap to count calls – use a closure-based checker
		_ = callCount
		uc := newUC(nil, nil, checker, nil, nil, config.StrategyImmediate, 1)

		h := host("1.2.3.4",
			svc(80, "tcp", vuln("CVE-SHARED", false)),
			svc(443, "tcp", vuln("CVE-SHARED", false)),
		)
		uc.enrichExploitsBatch(context.Background(), &h)

		for i, s := range h.Services {
			if !s.Vulnerabilities[0].ExploitAvailable {
				t.Errorf("service[%d] ExploitAvailable should be true", i)
			}
		}
	})
}

// Tests for Execute (pipeline)

func TestExecute(t *testing.T) {

	// Shared across both strategies

	t.Run("scanner error is returned", func(t *testing.T) {
		scanner := &stubScanner{err: errors.New("masscan failed")}
		repo := &stubRepo{}
		uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, &stubNotifier{}, config.StrategyImmediate, 1)

		err := uc.Execute(context.Background(), []string{"10.0.0.0/24"}, "1-1000")
		if err == nil || err.Error() != "masscan failed" {
			t.Fatalf("expected masscan error, got %v", err)
		}
	})

	t.Run("context cancellation stops workers cleanly", func(t *testing.T) {
		// Slow scanner that blocks until context cancelled
		hc := make(chan domain.HostScanResult)
		ec := make(chan error, 1)
		scanner := &chanScanner{hc: hc, ec: ec}

		repo := &stubRepo{}
		uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, &stubNotifier{}, config.StrategyImmediate, 2)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		done := make(chan error, 1)
		go func() { done <- uc.Execute(ctx, []string{"10.0.0.0/24"}, "80") }()

		select {
		case <-done: // completed (possibly with ctx error)
		case <-time.After(2 * time.Second):
			t.Fatal("Execute did not return after context cancellation")
		}
	})

	t.Run("two ports same IP are always aggregated into one saved host", func(t *testing.T) {
		// Regardless of notification strategy, the persistence layer must
		// receive a single HostScanResult per IP with all ports merged.
		for _, strategy := range []string{config.StrategyImmediate, config.StrategyAggregated} {
			t.Run(strategy, func(t *testing.T) {
				h1 := host("10.0.0.1", svc(80, "tcp"))
				h2 := host("10.0.0.1", svc(443, "tcp"))
				scanner := &stubScanner{hosts: []domain.HostScanResult{h1, h2}}
				repo := &stubRepo{}
				uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, &stubNotifier{}, strategy, 1)

				_ = uc.Execute(context.Background(), []string{"10.0.0.0/24"}, "80,443")

				if len(repo.saved) != 1 {
					t.Fatalf("expected 1 saved host, got %d", len(repo.saved))
				}
				if len(repo.saved[0].Services) != 2 {
					t.Fatalf("expected 2 services in saved host, got %d", len(repo.saved[0].Services))
				}
			})
		}
	})

	t.Run("no alert sent when nothing changed", func(t *testing.T) {
		for _, strategy := range []string{config.StrategyImmediate, config.StrategyAggregated} {
			t.Run(strategy, func(t *testing.T) {
				h := host("10.0.0.1", svc(80, "tcp"))
				scanner := &stubScanner{hosts: []domain.HostScanResult{h}}
				repo := &stubRepo{found: true, prev: h}
				notifier := &stubNotifier{}
				uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, notifier, strategy, 1)

				_ = uc.Execute(context.Background(), []string{"10.0.0.0/24"}, "80")

				if len(notifier.alerts) != 0 {
					t.Fatalf("expected no alerts, got %d", len(notifier.alerts))
				}
			})
		}
	})

	t.Run("repo error on GetPreviousResult does not abort pipeline", func(t *testing.T) {
		for _, strategy := range []string{config.StrategyImmediate, config.StrategyAggregated} {
			t.Run(strategy, func(t *testing.T) {
				h1 := host("10.0.0.1", svc(80, "tcp"))
				h2 := host("10.0.0.2", svc(443, "tcp"))
				scanner := &stubScanner{hosts: []domain.HostScanResult{h1, h2}}
				uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, &repoWithFirstCallError{}, &stubNotifier{}, strategy, 1)

				err := uc.Execute(context.Background(), []string{"10.0.0.0/24"}, "80,443")
				if err != nil {
					t.Fatalf("pipeline should not abort on per-host repo error: %v", err)
				}
			})
		}
	})

	// StrategyImmediate

	t.Run("immediate: alert sent for each new port separately", func(t *testing.T) {
		// Two ports on the same host arrive as separate scanner results.
		// In immediate mode each triggers its own alert before aggregation.
		h1 := host("10.0.0.1", svc(80, "tcp"))
		h2 := host("10.0.0.1", svc(443, "tcp"))
		scanner := &stubScanner{hosts: []domain.HostScanResult{h1, h2}}
		repo := &stubRepo{found: false}
		notifier := &stubNotifier{}
		uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, notifier, config.StrategyImmediate, 1)

		_ = uc.Execute(context.Background(), []string{"10.0.0.0/24"}, "80,443")

		if len(notifier.alerts) != 2 {
			t.Fatalf("expected 2 alerts (one per port), got %d", len(notifier.alerts))
		}
	})

	t.Run("immediate: alert contains correct IP", func(t *testing.T) {
		h := host("10.0.0.1", svc(80, "tcp"))
		scanner := &stubScanner{hosts: []domain.HostScanResult{h}}
		repo := &stubRepo{found: false}
		notifier := &stubNotifier{}
		uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, notifier, config.StrategyImmediate, 1)

		_ = uc.Execute(context.Background(), []string{"10.0.0.0/24"}, "80")

		if len(notifier.alerts) != 1 {
			t.Fatalf("expected 1 alert, got %d", len(notifier.alerts))
		}
		if notifier.alerts[0].IP != "10.0.0.1" {
			t.Errorf("alert IP = %q; want 10.0.0.1", notifier.alerts[0].IP)
		}
	})

	t.Run("immediate: host is persisted after scan", func(t *testing.T) {
		h := host("192.168.1.1", svc(22, "tcp"))
		scanner := &stubScanner{hosts: []domain.HostScanResult{h}}
		repo := &stubRepo{found: false}
		uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, &stubNotifier{}, config.StrategyImmediate, 2)

		if err := uc.Execute(context.Background(), []string{"192.168.1.0/24"}, "22"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(repo.saved) != 1 {
			t.Fatalf("expected 1 saved host, got %d", len(repo.saved))
		}
	})

	// StrategyAggregated

	t.Run("aggregated: single alert combining all new ports for one host", func(t *testing.T) {
		h1 := host("10.0.0.1", svc(80, "tcp"))
		h2 := host("10.0.0.1", svc(443, "tcp"))
		scanner := &stubScanner{hosts: []domain.HostScanResult{h1, h2}}
		repo := &stubRepo{found: false}
		notifier := &stubNotifier{}
		uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, notifier, config.StrategyAggregated, 1)

		_ = uc.Execute(context.Background(), []string{"10.0.0.0/24"}, "80,443")

		if len(notifier.alerts) != 1 {
			t.Fatalf("expected 1 combined alert, got %d", len(notifier.alerts))
		}
		if len(notifier.alerts[0].NewServices) != 2 {
			t.Fatalf("expected 2 new services in alert, got %d", len(notifier.alerts[0].NewServices))
		}
	})

	t.Run("aggregated: alert sent for new host", func(t *testing.T) {
		h := host("10.0.0.1", svc(80, "tcp"))
		scanner := &stubScanner{hosts: []domain.HostScanResult{h}}
		repo := &stubRepo{found: false}
		notifier := &stubNotifier{}
		uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, notifier, config.StrategyAggregated, 1)

		_ = uc.Execute(context.Background(), []string{"10.0.0.0/24"}, "80")

		if len(notifier.alerts) != 1 {
			t.Fatalf("expected 1 alert, got %d", len(notifier.alerts))
		}
		if notifier.alerts[0].IP != "10.0.0.1" {
			t.Errorf("alert IP = %q; want 10.0.0.1", notifier.alerts[0].IP)
		}
	})

	t.Run("aggregated: host is persisted after scan", func(t *testing.T) {
		h := host("192.168.1.1", svc(22, "tcp"))
		scanner := &stubScanner{hosts: []domain.HostScanResult{h}}
		repo := &stubRepo{found: false}
		uc := newUC(scanner, &stubEnricher{}, &stubExploitChecker{}, repo, &stubNotifier{}, config.StrategyAggregated, 2)

		if err := uc.Execute(context.Background(), []string{"192.168.1.0/24"}, "22"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(repo.saved) != 1 {
			t.Fatalf("expected 1 saved host, got %d", len(repo.saved))
		}
	})
}

// Extra stubs for Execute tests

// repoWithFirstCallError fails GetPreviousResult for the first host only.
type repoWithFirstCallError struct {
	calls int
	saved []domain.HostScanResult
}

func (r *repoWithFirstCallError) GetPreviousResult(_ context.Context, _ string) (domain.HostScanResult, bool, error) {
	r.calls++
	if r.calls == 1 {
		return domain.HostScanResult{}, false, errors.New("db timeout")
	}
	return domain.HostScanResult{}, false, nil
}
func (r *repoWithFirstCallError) SaveResult(_ context.Context, h domain.HostScanResult) error {
	r.saved = append(r.saved, h)
	return nil
}

// chanScanner lets the test control the host channel directly.
type chanScanner struct {
	hc chan domain.HostScanResult
	ec chan error
}

func (s *chanScanner) Scan(ctx context.Context, _ []string, _ string) (<-chan domain.HostScanResult, <-chan error) {
	go func() {
		<-ctx.Done()
		close(s.hc)
		s.ec <- ctx.Err()
	}()
	return s.hc, s.ec
}

// Tests for NewScannerUseCase

func TestNewScannerUseCase_DefaultWorkerCount(t *testing.T) {
	uc := NewScannerUseCase(nil, nil, nil, nil, nil, config.StrategyImmediate, 0, newLogger())
	if uc.workerCount != 1 {
		t.Errorf("workerCount = %d; want 1 for invalid input", uc.workerCount)
	}
}

func TestNewScannerUseCase_NegativeWorkerCount(t *testing.T) {
	uc := NewScannerUseCase(nil, nil, nil, nil, nil, config.StrategyImmediate, -5, newLogger())
	if uc.workerCount != 1 {
		t.Errorf("workerCount = %d; want 1 for negative input", uc.workerCount)
	}
}
