package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/modermatt44/portal/internal/detect"
	"github.com/modermatt44/portal/internal/target"
	"github.com/modermatt44/portal/internal/term"
)

func TestExpiry(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		notAfter time.Time
		want     string
	}{
		{now.Add(89*24*time.Hour + time.Hour), "2026-12-25 (89 days left)"},
		{now.Add(36 * time.Hour), "2026-09-29 (1 day left)"},
		{now.Add(-72 * time.Hour), "2026-09-24 (EXPIRED 3 days ago)"},
	}
	for _, tt := range tests {
		if got := expiry(tt.notAfter, now); got != tt.want {
			t.Errorf("expiry(%v) = %q, want %q", tt.notAfter, got, tt.want)
		}
	}
}

func TestPrintReportTLS(t *testing.T) {
	info := &detect.TLSInfo{
		Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2",
		Subject: "CN=example.com", Issuer: "CN=Test CA",
		NotAfter:    time.Now().Add(30 * 24 * time.Hour),
		VerifyError: "x509: certificate signed by unknown authority",
	}
	rep := &detect.Report{
		Target:     target.Target{Host: "example.com", Port: 443},
		TLS:        info,
		Candidates: []detect.Result{{Service: detect.HTTPS, Confidence: detect.Confirmed, Evidence: "ALPN h2", TLS: info}},
	}
	var b strings.Builder
	printReport(&b, term.Style{}, rep, "curl -v https://example.com")
	out := b.String()
	for _, want := range []string{
		"✓ HTTPS on example.com:443 (confirmed)",
		"tls       TLS 1.3 · TLS_AES_128_GCM_SHA256 · ALPN h2",
		"issuer    CN=Test CA",
		"trusted   no: x509: certificate signed by unknown authority",
		"client    curl -v https://example.com",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestPrintReportUnknown(t *testing.T) {
	rep := &detect.Report{Target: target.Target{Host: "h", Port: 1}, Banner: []byte("RFB 003.008\n")}
	var b strings.Builder
	printReport(&b, term.Style{}, rep, "(built-in raw TCP session)")
	if out := b.String(); !strings.Contains(out, "No known service detected on h:1") || !strings.Contains(out, `banner  "RFB 003.008"`) {
		t.Errorf("report = %q", out)
	}
}
