package telegram

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"perimeter-scanner/internal/domain"
)

// Helpers

func newAdapter(token, chatID string) *NotifierAdapter {
	return NewNotifierAdapter(token, chatID)
}

func vuln(cve string, score float64, exploit bool) domain.Vulnerability {
	return domain.Vulnerability{
		CVE:              cve,
		Score:            score,
		ExploitAvailable: exploit,
		Link:             "https://vulners.com/cve/" + cve,
	}
}

func svc(port int, proto, service string, vulns ...domain.Vulnerability) domain.ServiceInfo {
	return domain.ServiceInfo{Port: port, Proto: proto, Service: service, Vulnerabilities: vulns}
}

func diff(ip string, svcs ...domain.ServiceInfo) domain.ScanDiff {
	return domain.ScanDiff{
		IP:          ip,
		ScanTime:    time.Date(2026, 5, 7, 22, 0, 0, 0, time.UTC),
		NewServices: svcs,
	}
}

// Tests for escapeMarkdownV2

func TestEscapeMarkdownV2(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"plain text", "plain text"},
		{"192.168.1.1", "192\\.168\\.1\\.1"},
		{"hello_world", "hello\\_world"},
		{"*bold*", "\\*bold\\*"},
		{"[link](url)", "\\[link\\]\\(url\\)"},
		{"score=9.8!", "score\\=9\\.8\\!"},
		{"pipe|here", "pipe\\|here"},
		{"a+b=c", "a\\+b\\=c"},
		{"", ""},
	}

	for _, tc := range cases {
		got := escapeMarkdownV2(tc.input)
		if got != tc.want {
			t.Errorf("escapeMarkdownV2(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

// Tests for getSeverityEmoji

func TestGetSeverityEmoji(t *testing.T) {
	a := newAdapter("", "")
	cases := []struct {
		score float64
		want  string
	}{
		{10.0, "🔴"}, // Critical upper bound
		{9.0, "🔴"},  // Critical lower bound
		{8.9, "🟠"},  // High
		{7.0, "🟠"},  // High lower bound
		{6.9, "🟡"},  // Medium
		{4.0, "🟡"},  // Medium lower bound
		{3.9, "🟢"},  // Low
		{0.1, "🟢"},  // Low lower bound
		{0.0, "ℹ️"}, // Info / None
	}

	for _, tc := range cases {
		got := a.getSeverityEmoji(tc.score)
		if got != tc.want {
			t.Errorf("getSeverityEmoji(%.1f) = %q; want %q", tc.score, got, tc.want)
		}
	}
}

// Tests for splitMessage

func TestSplitMessage(t *testing.T) {
	a := newAdapter("", "")

	t.Run("short message is not split", func(t *testing.T) {
		parts := a.splitMessage("hello")
		if len(parts) != 1 || parts[0] != "hello" {
			t.Errorf("unexpected parts: %v", parts)
		}
	})

	t.Run("empty string returns single empty part", func(t *testing.T) {
		parts := a.splitMessage("")
		if len(parts) != 1 {
			t.Errorf("expected 1 part, got %d", len(parts))
		}
	})

	t.Run("message exactly at limit is not split", func(t *testing.T) {
		text := strings.Repeat("a", maxTelegramMessageLen)
		parts := a.splitMessage(text)
		if len(parts) != 1 {
			t.Errorf("expected 1 part, got %d", len(parts))
		}
	})

	t.Run("long message is split into multiple parts", func(t *testing.T) {
		// Build a message that is ~2.5x the limit using line-separated chunks
		line := strings.Repeat("x", 100) + "\n"
		repeat := (maxTelegramMessageLen*5/2)/len(line) + 1
		text := strings.Repeat(line, repeat)

		parts := a.splitMessage(text)
		if len(parts) < 2 {
			t.Errorf("expected >= 2 parts for a long message, got %d", len(parts))
		}
		for i, p := range parts {
			if len(p) > maxTelegramMessageLen {
				t.Errorf("part %d exceeds limit: len=%d", i, len(p))
			}
		}
	})

	t.Run("split parts reassemble to original content", func(t *testing.T) {
		line := strings.Repeat("y", 200) + "\n"
		repeat := maxTelegramMessageLen/len(line)*3 + 1
		original := strings.Repeat(line, repeat)

		parts := a.splitMessage(original)
		reassembled := strings.Join(parts, "")
		if reassembled != original {
			t.Error("reassembled content does not match original")
		}
	})
}

// Tests for buildMarkdownMessage

func TestBuildMarkdownMessage(t *testing.T) {
	a := newAdapter("", "")

	t.Run("contains host IP", func(t *testing.T) {
		msg := a.buildMarkdownMessage(diff("10.0.0.1", svc(80, "tcp", "http")))
		if !strings.Contains(msg, "10\\.0\\.0\\.1") {
			t.Error("message should contain escaped IP")
		}
	})

	t.Run("contains scan time", func(t *testing.T) {
		msg := a.buildMarkdownMessage(diff("10.0.0.1", svc(80, "tcp", "http")))
		if !strings.Contains(msg, "2026\\-05\\-07") {
			t.Error("message should contain escaped scan date")
		}
	})

	t.Run("contains port and proto", func(t *testing.T) {
		msg := a.buildMarkdownMessage(diff("10.0.0.1", svc(443, "tcp", "https")))
		if !strings.Contains(msg, "443/tcp") {
			t.Error("message should contain port/proto")
		}
	})

	t.Run("service with no vulns shows no-CVE notice", func(t *testing.T) {
		msg := a.buildMarkdownMessage(diff("10.0.0.1", svc(80, "tcp", "http")))
		if !strings.Contains(msg, "Известных CVE") {
			t.Error("message should mention no known CVEs")
		}
	})

	t.Run("exploit flag renders EXPLOIT marker", func(t *testing.T) {
		s := svc(22, "tcp", "ssh", vuln("CVE-2026-001", 9.8, true))
		msg := a.buildMarkdownMessage(diff("10.0.0.1", s))
		if !strings.Contains(msg, "EXPLOIT") {
			t.Error("message should contain EXPLOIT marker for exploitable vuln")
		}
	})

	t.Run("non-exploitable vuln has no EXPLOIT marker", func(t *testing.T) {
		s := svc(22, "tcp", "ssh", vuln("CVE-2026-001", 5.0, false))
		msg := a.buildMarkdownMessage(diff("10.0.0.1", s))
		if strings.Contains(msg, "EXPLOIT") {
			t.Error("message should NOT contain EXPLOIT marker")
		}
	})

	t.Run("CVE score is included", func(t *testing.T) {
		s := svc(80, "tcp", "http", vuln("CVE-2026-001", 7.5, false))
		msg := a.buildMarkdownMessage(diff("10.0.0.1", s))
		if !strings.Contains(msg, "7\\.5") {
			t.Error("message should contain escaped CVSS score")
		}
	})

	t.Run("CVE link is included", func(t *testing.T) {
		s := svc(80, "tcp", "http", vuln("CVE-2026-001", 7.5, false))
		msg := a.buildMarkdownMessage(diff("10.0.0.1", s))
		if !strings.Contains(msg, "vulners.com/cve/CVE-2026-001") {
			t.Error("message should contain CVE link")
		}
	})

	t.Run("last vuln uses └ prefix, others use ├", func(t *testing.T) {
		s := svc(80, "tcp", "http",
			vuln("CVE-2026-001", 9.0, false),
			vuln("CVE-2026-002", 5.0, false),
		)
		msg := a.buildMarkdownMessage(diff("10.0.0.1", s))
		if !strings.Contains(msg, "├") {
			t.Error("expected ├ prefix for non-last vuln")
		}
		if !strings.Contains(msg, "└") {
			t.Error("expected └ prefix for last vuln")
		}
	})

	t.Run("version shown when present", func(t *testing.T) {
		s := domain.ServiceInfo{Port: 22, Proto: "tcp", Service: "ssh", Version: "8.9p1"}
		msg := a.buildMarkdownMessage(diff("10.0.0.1", s))
		if !strings.Contains(msg, "8\\.9p1") {
			t.Error("message should contain escaped version string")
		}
	})

	t.Run("banner shown when present", func(t *testing.T) {
		s := domain.ServiceInfo{Port: 80, Proto: "tcp", Service: "http", Banner: "Apache 2.4"}
		msg := a.buildMarkdownMessage(diff("10.0.0.1", s))
		if !strings.Contains(msg, "Apache 2\\.4") {
			t.Error("message should contain escaped banner")
		}
	})
}

// Tests for sendMessage via httptest

func TestSendMessage(t *testing.T) {
	t.Run("success: 200 OK", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		a := newAdapter("test-token", "chat123")
		// Point the client to the test server by overriding the URL via a custom transport
		a.client = srv.Client()
		// Swap the base URL by patching the token so the URL resolves to the test server
		// Use a RoundTripper that rewrites the host instead
		a.client.Transport = rewriteHostTransport(srv.URL)

		err := a.sendMessage(context.Background(), "hello")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("non-200 returns error with status code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"description": "Unauthorized"})
		}))
		defer srv.Close()

		a := newAdapter("bad-token", "chat123")
		a.client = srv.Client()
		a.client.Transport = rewriteHostTransport(srv.URL)

		err := a.sendMessage(context.Background(), "hello")
		if err == nil {
			t.Fatal("expected error for non-200 response")
		}
		if !strings.Contains(err.Error(), "401") {
			t.Errorf("error should mention status code 401, got: %v", err)
		}
	})

	t.Run("token is redacted in network error", func(t *testing.T) {
		a := newAdapter("SECRET-TOKEN-123", "chat123")
		a.client = &http.Client{}

		// Call with a context that's already cancelled.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := a.sendMessage(ctx, "hello")
		if err == nil {
			t.Fatal("expected error for cancelled context")
		}
		if strings.Contains(err.Error(), "SECRET-TOKEN-123") {
			t.Errorf("token must be redacted in error message, got: %v", err)
		}
	})

	t.Run("request carries correct Content-Type header", func(t *testing.T) {
		var gotContentType string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotContentType = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		a := newAdapter("tok", "chat")
		a.client = srv.Client()
		a.client.Transport = rewriteHostTransport(srv.URL)

		_ = a.sendMessage(context.Background(), "hi")
		if gotContentType != "application/json" {
			t.Errorf("Content-Type = %q; want application/json", gotContentType)
		}
	})

	t.Run("request body contains correct chat_id and parse_mode", func(t *testing.T) {
		var body telegramMessage
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		a := newAdapter("tok", "MY-CHAT-ID")
		a.client = srv.Client()
		a.client.Transport = rewriteHostTransport(srv.URL)

		_ = a.sendMessage(context.Background(), "test text")
		if body.ChatID != "MY-CHAT-ID" {
			t.Errorf("chat_id = %q; want MY-CHAT-ID", body.ChatID)
		}
		if body.ParseMode != "MarkdownV2" {
			t.Errorf("parse_mode = %q; want MarkdownV2", body.ParseMode)
		}
		if !body.DisableWebPagePreview {
			t.Error("disable_web_page_preview should be true")
		}
	})
}

// Tests for SendDiffAlert

func TestSendDiffAlert(t *testing.T) {
	t.Run("empty NewServices: no HTTP call is made", func(t *testing.T) {
		called := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		a := newAdapter("tok", "chat")
		a.client = srv.Client()
		a.client.Transport = rewriteHostTransport(srv.URL)

		err := a.SendDiffAlert(context.Background(), domain.ScanDiff{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if called {
			t.Error("HTTP should not be called for empty diff")
		}
	})

	t.Run("single service: exactly one HTTP call", func(t *testing.T) {
		callCount := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		a := newAdapter("tok", "chat")
		a.client = srv.Client()
		a.client.Transport = rewriteHostTransport(srv.URL)

		d := diff("10.0.0.1", svc(80, "tcp", "http"))
		err := a.SendDiffAlert(context.Background(), d)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if callCount != 1 {
			t.Errorf("expected 1 HTTP call, got %d", callCount)
		}
	})

	t.Run("API error is propagated", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		a := newAdapter("tok", "chat")
		a.client = srv.Client()
		a.client.Transport = rewriteHostTransport(srv.URL)

		err := a.SendDiffAlert(context.Background(), diff("10.0.0.1", svc(80, "tcp", "http")))
		if err == nil {
			t.Fatal("expected error for 403 response")
		}
	})
}

// rewriteHostTransport redirects all requests to the given base URL,
// preserving the path and query. This lets tests use httptest.Server
// without changing production code URLs.
type rewriteHostTransportType struct{ base string }

func rewriteHostTransport(base string) *rewriteHostTransportType {
	return &rewriteHostTransportType{base: base}
}

func (t *rewriteHostTransportType) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(t.base, "http://")
	return http.DefaultTransport.RoundTrip(req)
}
