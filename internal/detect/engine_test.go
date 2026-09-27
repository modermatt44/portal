package detect

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/modermatt44/portal/internal/fakeserver"
	"github.com/modermatt44/portal/internal/target"
)

// testOptions returns short timeouts suitable for loopback tests, using
// every registered prober.
func testOptions(t *testing.T) Options {
	return Options{
		Timeout:       5 * time.Second,
		BannerTimeout: 300 * time.Millisecond,
		TLSTimeout:    time.Second,
		ProbeTimeout:  time.Second,
		Logf:          t.Logf,
	}
}

// detectFake runs Detect against s and fails the test on error.
func detectFake(t *testing.T, s *fakeserver.Server) *Report {
	t.Helper()
	rep, err := Detect(context.Background(), s.Target, testOptions(t))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return rep
}

// wantBest asserts that the report picks service with the given confidence.
func wantBest(t *testing.T, rep *Report, service Service, conf Confidence) Result {
	t.Helper()
	best, ok := rep.Best()
	if !ok {
		t.Fatalf("Best() found nothing; candidates: %+v", rep.Candidates)
	}
	if best.Service != service || best.Confidence != conf {
		t.Fatalf("Best() = %s (%s), want %s (%s); candidates: %+v", best.Service, best.Confidence, service, conf, rep.Candidates)
	}
	return best
}

func TestDetectConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	_, err = Detect(context.Background(), target.Target{Host: "127.0.0.1", Port: port}, testOptions(t))
	var ce *ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("Detect error = %v, want *ConnError", err)
	}
}

func TestDetectUnknownBanner(t *testing.T) {
	s := fakeserver.Start(t, fakeserver.Lines("RFB 003.008\n", nil))
	rep := detectFake(t, s)
	if len(rep.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none", rep.Candidates)
	}
	if string(rep.Banner) != "RFB 003.008\n" {
		t.Errorf("banner = %q", rep.Banner)
	}
}

func TestDetectSilent(t *testing.T) {
	s := fakeserver.Start(t, fakeserver.Silent())
	rep := detectFake(t, s)
	if len(rep.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none", rep.Candidates)
	}
	if _, ok := rep.Best(); ok {
		t.Error("Best() found a service on a silent port")
	}
}

func TestReportBest(t *testing.T) {
	tests := []struct {
		name  string
		cands []Result
		want  Service
		ok    bool
	}{
		{"empty", nil, "", false},
		{"single confirmed", []Result{{Service: SSH, Confidence: Confirmed}}, SSH, true},
		{"single likely", []Result{{Service: SMTP, Confidence: Likely}}, SMTP, true},
		{"confirmed beats possible", []Result{{Service: FTP, Confidence: Confirmed}, {Service: SMTP, Confidence: Possible}}, FTP, true},
		{"tie is ambiguous", []Result{{Service: FTP, Confidence: Possible}, {Service: SMTP, Confidence: Possible}}, "", false},
		{"two confirmed is ambiguous", []Result{{Service: HTTP, Confidence: Confirmed}, {Service: Redis, Confidence: Confirmed}}, "", false},
		{"port hint alone is not enough", []Result{{Service: PostgreSQL, Confidence: PortHint}}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := (&Report{Candidates: tt.cands}).Best()
			if ok != tt.ok || got.Service != tt.want {
				t.Errorf("Best() = %s, %v; want %s, %v", got.Service, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestMergeAndSort(t *testing.T) {
	in := []Result{
		{Service: SMTP, Confidence: Possible},
		{Service: FTP, Confidence: Possible},
		{Service: SMTP, Confidence: Confirmed},
	}
	out := merge(in)
	if len(out) != 2 || out[0].Confidence != Confirmed {
		t.Fatalf("merge = %+v", out)
	}

	tie := []Result{{Service: SMTP, Confidence: Possible}, {Service: FTP, Confidence: Possible}}
	sortResults(tie, FTP)
	if tie[0].Service != FTP {
		t.Errorf("port hint should break ties: got %+v", tie)
	}
}

func TestResultLabel(t *testing.T) {
	tests := []struct {
		r    Result
		want string
	}{
		{Result{Service: PostgreSQL}, "PostgreSQL"},
		{Result{Service: MySQL, Product: "MySQL", Version: "8.0.36"}, "MySQL 8.0.36"},
		{Result{Service: SSH, Product: "OpenSSH", Version: "9.6p1"}, "SSH (OpenSSH 9.6p1)"},
		{Result{Service: HTTP, Product: "nginx/1.25.3"}, "HTTP (nginx/1.25.3)"},
		{Result{Service: Redis, Version: "7.2.4"}, "Redis 7.2.4"},
	}
	for _, tt := range tests {
		if got := tt.r.Label(); got != tt.want {
			t.Errorf("Label() = %q, want %q", got, tt.want)
		}
	}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registering a duplicate prober did not panic")
		}
	}()
	Register(sshProber{})
}

func TestVersionToken(t *testing.T) {
	tests := map[string]string{
		"4.96 Mon, 1 Jan": "4.96",
		"3.0.5)":          "3.0.5",
		"8.15.2/8.15.2;":  "8.15.2",
		"(Ubuntu)":        "",
		"":                "",
	}
	for in, want := range tests {
		if got := versionToken(in); got != want {
			t.Errorf("versionToken(%q) = %q, want %q", in, got, want)
		}
	}
}
