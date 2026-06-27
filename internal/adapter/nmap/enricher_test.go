package nmap

import (
	"log/slog"
	"os"
	"testing"

	gonmap "github.com/Ullaakut/nmap/v4"
)

func newAdapter() *EnricherAdapter {
	return NewEnricherAdapter(slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

// Tests for buildBanner

func TestBuildBanner(t *testing.T) {
	cases := []struct {
		name string
		svc  gonmap.Service
		want string
	}{
		{
			name: "all fields filled",
			svc:  gonmap.Service{Product: "Apache httpd", Version: "2.4.51", ExtraInfo: "Debian"},
			want: "Apache httpd 2.4.51 Debian",
		},
		{
			name: "product and version only",
			svc:  gonmap.Service{Product: "OpenSSH", Version: "8.9p1"},
			want: "OpenSSH 8.9p1",
		},
		{
			name: "product only",
			svc:  gonmap.Service{Product: "nginx"},
			want: "nginx",
		},
		{
			name: "version only",
			svc:  gonmap.Service{Version: "3.2.1"},
			want: "3.2.1",
		},
		{
			name: "extra info only",
			svc:  gonmap.Service{ExtraInfo: "protocol 2.0"},
			want: "protocol 2.0",
		},
		{
			name: "empty service",
			svc:  gonmap.Service{},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildBanner(tc.svc)
			if got != tc.want {
				t.Errorf("got %q; want %q", got, tc.want)
			}
		})
	}
}

// Tests for parseVulnersScript

func makeVulnTable(id, typ, cvss string) gonmap.Table {
	return gonmap.Table{
		Elements: []gonmap.Element{
			{Key: "id", Value: id},
			{Key: "type", Value: typ},
			{Key: "cvss", Value: cvss},
		},
	}
}

func makeVulnersScript(vulnTables ...gonmap.Table) []gonmap.Script {
	return []gonmap.Script{
		{
			ID: "vulners",
			Tables: []gonmap.Table{
				{Tables: vulnTables},
			},
		},
	}
}

func TestParseVulnersScript(t *testing.T) {
	a := newAdapter()

	t.Run("returns nil for empty scripts", func(t *testing.T) {
		got := a.parseVulnersScript(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("ignores scripts with wrong ID", func(t *testing.T) {
		scripts := []gonmap.Script{{ID: "http-title", Tables: []gonmap.Table{{Tables: []gonmap.Table{makeVulnTable("CVE-2023-38408", "cve", "9.8")}}}}}
		got := a.parseVulnersScript(scripts)
		if len(got) != 0 {
			t.Errorf("expected 0 vulns, got %d", len(got))
		}
	})

	t.Run("parses single CVE correctly", func(t *testing.T) {
		scripts := makeVulnersScript(makeVulnTable("CVE-2023-38408", "cve", "9.8"))
		got := a.parseVulnersScript(scripts)

		if len(got) != 1 {
			t.Fatalf("expected 1 vuln, got %d", len(got))
		}
		v := got[0]
		if v.CVE != "CVE-2023-38408" {
			t.Errorf("CVE = %q; want CVE-2023-38408", v.CVE)
		}
		if v.Score != 9.8 {
			t.Errorf("Score = %v; want 9.8", v.Score)
		}
		if v.Link != "https://vulners.com/cve/CVE-2023-38408" {
			t.Errorf("Link = %q; unexpected", v.Link)
		}
	})

	t.Run("parses multiple CVEs", func(t *testing.T) {
		scripts := makeVulnersScript(
			makeVulnTable("CVE-2026-001", "cve", "9.8"),
			makeVulnTable("CVE-2026-002", "cve", "7.5"),
			makeVulnTable("CVE-2026-003", "cve", "4.0"),
		)
		got := a.parseVulnersScript(scripts)
		if len(got) != 3 {
			t.Fatalf("expected 3 vulns, got %d", len(got))
		}
	})

	t.Run("skips non-CVE entries: EDB-ID", func(t *testing.T) {
		scripts := makeVulnersScript(
			makeVulnTable("EDB-ID:12345", "exploitdb", "9.0"),
			makeVulnTable("CVE-2026-001", "cve", "7.0"),
		)
		got := a.parseVulnersScript(scripts)
		if len(got) != 1 || got[0].CVE != "CVE-2026-001" {
			t.Errorf("expected only CVE entry, got %v", got)
		}
	})

	t.Run("skips non-CVE entries: PACKETSTORM", func(t *testing.T) {
		scripts := makeVulnersScript(makeVulnTable("PACKETSTORM:12345", "packetstorm", "8.0"))
		got := a.parseVulnersScript(scripts)
		if len(got) != 0 {
			t.Errorf("expected 0 vulns, got %d", len(got))
		}
	})

	t.Run("skips non-CVE entries: MSF", func(t *testing.T) {
		scripts := makeVulnersScript(makeVulnTable("MSF:EXPLOIT/UNIX/FTP", "metasploit", "10.0"))
		got := a.parseVulnersScript(scripts)
		if len(got) != 0 {
			t.Errorf("expected 0 vulns, got %d", len(got))
		}
	})

	t.Run("skips entry with empty id", func(t *testing.T) {
		scripts := makeVulnersScript(makeVulnTable("", "cve", "5.0"))
		got := a.parseVulnersScript(scripts)
		if len(got) != 0 {
			t.Errorf("expected 0 vulns (empty id), got %d", len(got))
		}
	})

	t.Run("invalid CVSS score defaults to 0", func(t *testing.T) {
		scripts := makeVulnersScript(makeVulnTable("CVE-2024-001", "cve", "not-a-number"))
		got := a.parseVulnersScript(scripts)
		if len(got) != 1 {
			t.Fatalf("expected 1 vuln, got %d", len(got))
		}
		if got[0].Score != 0 {
			t.Errorf("Score = %v; want 0 for unparseable value", got[0].Score)
		}
	})

	t.Run("zero CVSS score is preserved", func(t *testing.T) {
		scripts := makeVulnersScript(makeVulnTable("CVE-2024-001", "cve", "0.0"))
		got := a.parseVulnersScript(scripts)
		if got[0].Score != 0.0 {
			t.Errorf("Score = %v; want 0.0", got[0].Score)
		}
	})
}
