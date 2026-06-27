package postgres

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"perimeter-scanner/internal/domain"
)

// Helpers

func nullText() pgtype.Text       { return pgtype.Text{Valid: false} }
func text(s string) pgtype.Text   { return pgtype.Text{String: s, Valid: true} }
func nullNumeric() pgtype.Numeric { return pgtype.Numeric{Valid: false} }
func nullBool() pgtype.Bool       { return pgtype.Bool{Valid: false} }

func numericFromFloat(t *testing.T, f float64) pgtype.Numeric {
	t.Helper()
	n, err := scoreToNumeric(f)
	if err != nil {
		t.Fatalf("scoreToNumeric(%v): %v", f, err)
	}
	return n
}

func baseRow(serviceID int32, port int32, proto string) GetServicesWithVulnerabilitiesRow {
	return GetServicesWithVulnerabilitiesRow{
		ServiceID:        serviceID,
		Port:             port,
		Proto:            proto,
		Service:          nullText(),
		Banner:           nullText(),
		Version:          nullText(),
		Cpe:              nullText(),
		Cve:              nullText(),
		Score:            nullNumeric(),
		ExploitAvailable: nullBool(),
		Link:             nullText(),
	}
}

// Tests for scoreToNumeric

func TestScoreToNumeric(t *testing.T) {
	cases := []struct {
		score   float64
		wantStr string
	}{
		{9.8, "9.8"},
		{7.5, "7.5"},
		{0.0, "0.0"},
		{10.0, "10.0"},
		{4.35, "4.3"}, // one decimal place: rounds
	}

	for _, tc := range cases {
		n, err := scoreToNumeric(tc.score)
		if err != nil {
			t.Errorf("scoreToNumeric(%v) unexpected error: %v", tc.score, err)
			continue
		}
		if !n.Valid {
			t.Errorf("scoreToNumeric(%v): Numeric.Valid = false", tc.score)
			continue
		}
		// Round-trip: scan back to string via pgtype
		var got pgtype.Numeric
		if err := got.Scan(tc.wantStr); err != nil {
			t.Fatalf("reference scan failed: %v", err)
		}
		// Compare the decimal representation
		gotStr, err := n.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON failed: %v", err)
		}
		wantJSON, _ := got.MarshalJSON()
		if string(gotStr) != string(wantJSON) {
			t.Errorf("scoreToNumeric(%v) = %s; want %s", tc.score, gotStr, wantJSON)
		}
	}
}

// Tests for buildServicesFromRows

func TestBuildServicesFromRows_Empty(t *testing.T) {
	result := buildServicesFromRows(nil)
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %d elements", len(result))
	}
}

func TestBuildServicesFromRows_SingleServiceNoVulns(t *testing.T) {
	rows := []GetServicesWithVulnerabilitiesRow{
		func() GetServicesWithVulnerabilitiesRow {
			r := baseRow(1, 80, "tcp")
			r.Service = text("http")
			r.Banner = text("nginx 1.24")
			r.Version = text("1.24")
			r.Cpe = text("cpe:/a:nginx:nginx:1.24")
			return r
		}(),
	}

	got := buildServicesFromRows(rows)

	if len(got) != 1 {
		t.Fatalf("expected 1 service, got %d", len(got))
	}
	svc := got[0]
	if svc.Port != 80 {
		t.Errorf("Port = %d; want 80", svc.Port)
	}
	if svc.Proto != "tcp" {
		t.Errorf("Proto = %q; want tcp", svc.Proto)
	}
	if svc.Service != "http" {
		t.Errorf("Service = %q; want http", svc.Service)
	}
	if svc.Banner != "nginx 1.24" {
		t.Errorf("Banner = %q; want 'nginx 1.24'", svc.Banner)
	}
	if svc.CPE != "cpe:/a:nginx:nginx:1.24" {
		t.Errorf("CPE = %q; want cpe:/a:nginx:nginx:1.24", svc.CPE)
	}
	if len(svc.Vulnerabilities) != 0 {
		t.Errorf("expected no vulnerabilities, got %d", len(svc.Vulnerabilities))
	}
}

func TestBuildServicesFromRows_SingleServiceWithVulns(t *testing.T) {
	makeRow := func(cve string, score float64, exploit bool, link string) GetServicesWithVulnerabilitiesRow {
		r := baseRow(1, 443, "tcp")
		r.Cve = text(cve)
		r.Score = numericFromFloat(t, score)
		r.ExploitAvailable = pgtype.Bool{Bool: exploit, Valid: true}
		r.Link = text(link)
		return r
	}

	rows := []GetServicesWithVulnerabilitiesRow{
		makeRow("CVE-2026-001", 9.8, true, "https://vulners.com/cve/CVE-2026-001"),
		makeRow("CVE-2026-002", 7.5, false, "https://vulners.com/cve/CVE-2026-002"),
	}

	got := buildServicesFromRows(rows)

	if len(got) != 1 {
		t.Fatalf("expected 1 service, got %d", len(got))
	}
	if len(got[0].Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(got[0].Vulnerabilities))
	}

	// Find each CVE regardless of order
	byID := make(map[string]domain.Vulnerability)
	for _, v := range got[0].Vulnerabilities {
		byID[v.CVE] = v
	}

	v1, ok := byID["CVE-2026-001"]
	if !ok {
		t.Fatal("CVE-2026-001 missing")
	}
	if !v1.ExploitAvailable {
		t.Error("CVE-2026-001: ExploitAvailable should be true")
	}
	if v1.Score != 9.8 {
		t.Errorf("CVE-2026-001: Score = %v; want 9.8", v1.Score)
	}

	v2, ok := byID["CVE-2026-002"]
	if !ok {
		t.Fatal("CVE-2026-002 missing")
	}
	if v2.ExploitAvailable {
		t.Error("CVE-2026-002: ExploitAvailable should be false")
	}
}

func TestBuildServicesFromRows_MultipleServices(t *testing.T) {
	rows := []GetServicesWithVulnerabilitiesRow{
		func() GetServicesWithVulnerabilitiesRow {
			r := baseRow(1, 22, "tcp")
			r.Service = text("ssh")
			return r
		}(),
		func() GetServicesWithVulnerabilitiesRow {
			r := baseRow(2, 80, "tcp")
			r.Service = text("http")
			return r
		}(),
		func() GetServicesWithVulnerabilitiesRow {
			r := baseRow(3, 53, "udp")
			r.Service = text("dns")
			return r
		}(),
	}

	got := buildServicesFromRows(rows)

	if len(got) != 3 {
		t.Fatalf("expected 3 services, got %d", len(got))
	}
}

func TestBuildServicesFromRows_VulnsGroupedByService(t *testing.T) {
	// Service 1 has 2 vulns, service 2 has 1 vuln — all mixed in rows
	makeRow := func(svcID int32, port int32, cve string) GetServicesWithVulnerabilitiesRow {
		r := baseRow(svcID, port, "tcp")
		r.Cve = text(cve)
		r.Score = numericFromFloat(t, 5.0)
		r.ExploitAvailable = pgtype.Bool{Bool: false, Valid: true}
		r.Link = text("https://example.com")
		return r
	}

	rows := []GetServicesWithVulnerabilitiesRow{
		makeRow(1, 80, "CVE-2026-001"),
		makeRow(2, 443, "CVE-2026-003"),
		makeRow(1, 80, "CVE-2026-002"), // second vuln for service 1
	}

	got := buildServicesFromRows(rows)

	if len(got) != 2 {
		t.Fatalf("expected 2 services, got %d", len(got))
	}

	byPort := make(map[int]domain.ServiceInfo)
	for _, s := range got {
		byPort[s.Port] = s
	}

	if len(byPort[80].Vulnerabilities) != 2 {
		t.Errorf("port 80: expected 2 vulns, got %d", len(byPort[80].Vulnerabilities))
	}
	if len(byPort[443].Vulnerabilities) != 1 {
		t.Errorf("port 443: expected 1 vuln, got %d", len(byPort[443].Vulnerabilities))
	}
}

func TestBuildServicesFromRows_NullFieldsMapToEmptyStrings(t *testing.T) {
	rows := []GetServicesWithVulnerabilitiesRow{baseRow(1, 8080, "tcp")}

	got := buildServicesFromRows(rows)

	if len(got) != 1 {
		t.Fatalf("expected 1 service, got %d", len(got))
	}
	svc := got[0]
	if svc.Service != "" {
		t.Errorf("Service = %q; want empty string for NULL", svc.Service)
	}
	if svc.Banner != "" {
		t.Errorf("Banner = %q; want empty string for NULL", svc.Banner)
	}
	if svc.Version != "" {
		t.Errorf("Version = %q; want empty string for NULL", svc.Version)
	}
	if svc.CPE != "" {
		t.Errorf("CPE = %q; want empty string for NULL", svc.CPE)
	}
}
