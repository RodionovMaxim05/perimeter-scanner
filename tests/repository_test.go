//go:build integration

package tests

import (
	"context"
	"testing"
	"time"

	"perimeter-scanner/internal/domain"
)

// Test data builders

func testHost(ip string, svcs ...domain.ServiceInfo) domain.HostScanResult {
	return domain.HostScanResult{
		IP:       ip,
		ScanTime: time.Now().UTC().Truncate(time.Microsecond),
		Services: svcs,
	}
}

func testSvc(port int, proto, service string, vulns ...domain.Vulnerability) domain.ServiceInfo {
	return domain.ServiceInfo{
		Port:            port,
		Proto:           proto,
		Service:         service,
		Version:         "1.0",
		Banner:          "Test Banner",
		CPE:             "cpe:/a:test:test:1.0",
		Vulnerabilities: vulns,
	}
}

func testVuln(cve string, score float64, exploit bool) domain.Vulnerability {
	return domain.Vulnerability{
		CVE:              cve,
		Score:            score,
		ExploitAvailable: exploit,
		Link:             "https://vulners.com/cve/" + cve,
	}
}

// Tests for GetPreviousResult

func TestRepository_GetPreviousResult_NotFound(t *testing.T) {
	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	_, found, err := repo.GetPreviousResult(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected found=false for unknown IP")
	}
}

func TestRepository_GetPreviousResult_InvalidIP(t *testing.T) {
	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	_, _, err := repo.GetPreviousResult(context.Background(), "not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP format")
	}
}

// Tests for SaveResult

func TestRepository_SaveResult_InvalidIP(t *testing.T) {
	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	err := repo.SaveResult(context.Background(), domain.HostScanResult{IP: "bad-ip"})
	if err == nil {
		t.Error("expected error for invalid IP format")
	}
}

// Save -> Get roundtrip

func TestRepository_SaveAndGet_ServiceWithoutVulns(t *testing.T) {
	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	original := testHost("192.0.2.10",
		testSvc(80, "tcp", "http"),
		testSvc(443, "tcp", "https"),
	)

	if err := repo.SaveResult(context.Background(), original); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}

	got, found, err := repo.GetPreviousResult(context.Background(), original.IP)
	if err != nil {
		t.Fatalf("GetPreviousResult: %v", err)
	}
	if !found {
		t.Fatal("expected found=true after save")
	}
	if len(got.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(got.Services))
	}
	for _, svc := range got.Services {
		if len(svc.Vulnerabilities) != 0 {
			t.Errorf("port %d: expected no vulns, got %d", svc.Port, len(svc.Vulnerabilities))
		}
	}
}

func TestRepository_SaveAndGet_ServiceWithVulns(t *testing.T) {
	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	original := testHost("192.0.2.11",
		testSvc(22, "tcp", "ssh",
			testVuln("CVE-2026-0001", 9.8, true),
			testVuln("CVE-2026-0002", 7.5, false),
		),
	)

	if err := repo.SaveResult(context.Background(), original); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}

	got, found, err := repo.GetPreviousResult(context.Background(), original.IP)
	if err != nil {
		t.Fatalf("GetPreviousResult: %v", err)
	}
	if !found {
		t.Fatal("expected found=true after save")
	}
	if len(got.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(got.Services))
	}

	svc := got.Services[0]
	if svc.Port != 22 {
		t.Errorf("Port = %d; want 22", svc.Port)
	}
	if svc.Service != "ssh" {
		t.Errorf("Service = %q; want ssh", svc.Service)
	}
	if len(svc.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(svc.Vulnerabilities))
	}

	byID := make(map[string]domain.Vulnerability)
	for _, v := range svc.Vulnerabilities {
		byID[v.CVE] = v
	}

	v1, ok := byID["CVE-2026-0001"]
	if !ok {
		t.Fatal("CVE-2026-0001 missing")
	}
	if v1.Score != 9.8 {
		t.Errorf("Score = %.1f; want 9.8", v1.Score)
	}
	if !v1.ExploitAvailable {
		t.Error("ExploitAvailable should be true")
	}
	if v1.Link != "https://vulners.com/cve/CVE-2026-0001" {
		t.Errorf("Link = %q; unexpected", v1.Link)
	}

	v2, ok := byID["CVE-2026-0002"]
	if !ok {
		t.Fatal("CVE-2026-0002 missing")
	}
	if v2.ExploitAvailable {
		t.Error("ExploitAvailable should be false")
	}
}

func TestRepository_SaveAndGet_AllServiceFields(t *testing.T) {
	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	original := testHost("192.0.2.12",
		domain.ServiceInfo{
			Port:            8080,
			Proto:           "tcp",
			Service:         "http-alt",
			Version:         "2.4.51",
			Banner:          "Apache httpd 2.4.51",
			CPE:             "cpe:/a:apache:http_server:2.4.51",
			Vulnerabilities: nil,
		},
	)

	if err := repo.SaveResult(context.Background(), original); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}

	got, _, err := repo.GetPreviousResult(context.Background(), original.IP)
	if err != nil {
		t.Fatalf("GetPreviousResult: %v", err)
	}

	svc := got.Services[0]
	if svc.Version != "2.4.51" {
		t.Errorf("Version = %q; want 2.4.51", svc.Version)
	}
	if svc.Banner != "Apache httpd 2.4.51" {
		t.Errorf("Banner = %q; want 'Apache httpd 2.4.51'", svc.Banner)
	}
	if svc.CPE != "cpe:/a:apache:http_server:2.4.51" {
		t.Errorf("CPE = %q; unexpected", svc.CPE)
	}
}

// Replace-on-save behaviour

func TestRepository_SecondSave_ReplacesServices(t *testing.T) {
	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	ip := "192.0.2.20"

	// First scan: ports 22 and 80
	firstScan := testHost(ip, testSvc(22, "tcp", "ssh"), testSvc(80, "tcp", "http"))
	if err := repo.SaveResult(context.Background(), firstScan); err != nil {
		t.Fatalf("first SaveResult: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	// Second scan: only port 443 - ports 22 and 80 are now closed
	secondScan := testHost(ip, testSvc(443, "tcp", "https"))
	if err := repo.SaveResult(context.Background(), secondScan); err != nil {
		t.Fatalf("second SaveResult: %v", err)
	}

	got, found, err := repo.GetPreviousResult(context.Background(), ip)
	if err != nil {
		t.Fatalf("GetPreviousResult: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}

	// Only port 443 should remain; stale ports 22 and 80 must be gone
	if len(got.Services) != 1 {
		t.Fatalf("expected 1 service after replace, got %d", len(got.Services))
	}
	if got.Services[0].Port != 443 {
		t.Errorf("expected port 443, got %d", got.Services[0].Port)
	}
}

func TestRepository_SecondSave_UpdatesScanTime(t *testing.T) {
	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	ip := "192.0.2.21"

	firstScan := testHost(ip, testSvc(80, "tcp", "http"))
	if err := repo.SaveResult(context.Background(), firstScan); err != nil {
		t.Fatalf("first SaveResult: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	secondScan := testHost(ip, testSvc(80, "tcp", "http"))
	if err := repo.SaveResult(context.Background(), secondScan); err != nil {
		t.Fatalf("second SaveResult: %v", err)
	}

	got, _, err := repo.GetPreviousResult(context.Background(), ip)
	if err != nil {
		t.Fatalf("GetPreviousResult: %v", err)
	}

	// scan_time must reflect the second scan, not the first
	if !got.ScanTime.Equal(secondScan.ScanTime) {
		t.Errorf("ScanTime = %v; want %v", got.ScanTime, secondScan.ScanTime)
	}
}

// CVE upsert

func TestRepository_Upsert_CVEScoreUpdated(t *testing.T) {
	pool := newTestPool(t)
	cleanDB(t, pool)
	repo := newTestRepo(t, pool)

	ip := "192.0.2.30"

	firstScan := testHost(ip, testSvc(22, "tcp", "ssh", testVuln("CVE-2026-UPSERT", 7.5, false)))
	if err := repo.SaveResult(context.Background(), firstScan); err != nil {
		t.Fatalf("first SaveResult: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	secondScan := testHost(ip, testSvc(22, "tcp", "ssh", testVuln("CVE-2026-UPSERT", 9.8, true)))
	if err := repo.SaveResult(context.Background(), secondScan); err != nil {
		t.Fatalf("second SaveResult: %v", err)
	}

	got, _, err := repo.GetPreviousResult(context.Background(), ip)
	if err != nil {
		t.Fatalf("GetPreviousResult: %v", err)
	}

	v := got.Services[0].Vulnerabilities[0]
	if v.Score != 9.8 {
		t.Errorf("Score = %.1f; want 9.8 after upsert", v.Score)
	}
	if !v.ExploitAvailable {
		t.Error("ExploitAvailable should be true after upsert")
	}
}
