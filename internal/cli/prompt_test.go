package cli

import (
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

// ambiguousServer greets with a bare "220" and rejects both EHLO and FEAT,
// so SMTP and FTP remain equally possible.
func ambiguousServer(t *testing.T) *fakeserver.Server {
	return fakeserver.Start(t, fakeserver.Lines("220 ready\r\n", func(string) (string, bool) {
		return "500 what?\r\n", false
	}))
}

func TestChooserWithoutTTY(t *testing.T) {
	s := ambiguousServer(t)
	code, _, stderr := runCLI(t, "", "-n", s.Target.String())
	if code != ExitUsage {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "--service") || !strings.Contains(stderr, "FTP or SMTP") {
		t.Errorf("stderr = %q, want the candidates and a --service hint", stderr)
	}
}

func TestChooserPicksRaw(t *testing.T) {
	s := ambiguousServer(t)
	code, stdout, stderr := runCLIWith(t, cliEnv{tty: true}, "7\n3\n", "-n", s.Target.String())
	if code != ExitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{"Several services could be on", "1) FTP", "2) SMTP", "3) raw TCP session", "between 1 and 3"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want %q", stderr, want)
		}
	}
	if !strings.Contains(stdout, "raw TCP session") {
		t.Errorf("stdout = %q, want the raw session", stdout)
	}
}

func TestChooserQuit(t *testing.T) {
	s := ambiguousServer(t)
	code, _, stderr := runCLIWith(t, cliEnv{tty: true}, "q\n", "-n", s.Target.String())
	if code != ExitUsage || !strings.Contains(stderr, "aborted") {
		t.Errorf("exit code = %d, stderr = %q; want %d and 'aborted'", code, stderr, ExitUsage)
	}
}

func TestChooserEOF(t *testing.T) {
	s := ambiguousServer(t)
	code, _, stderr := runCLIWith(t, cliEnv{tty: true}, "", "-n", s.Target.String())
	if code != ExitUsage || !strings.Contains(stderr, "no choice made") {
		t.Errorf("exit code = %d, stderr = %q", code, stderr)
	}
}

func TestParseService(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		tls     bool
		wantErr bool
	}{
		{"redis", "redis", false, false},
		{"Postgres", "postgresql", false, false},
		{"mariadb", "mysql", false, false},
		{"https", "https", true, false},
		{"raw", "unknown", false, false},
		{"tls", "unknown", true, false},
		{"gopher", "", false, true},
	}
	for _, tt := range tests {
		r, err := parseService(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseService(%q) error = %v", tt.in, err)
			continue
		}
		if err == nil && (string(r.Service) != tt.want || (r.TLS != nil) != tt.tls) {
			t.Errorf("parseService(%q) = %s tls=%v, want %s tls=%v", tt.in, r.Service, r.TLS != nil, tt.want, tt.tls)
		}
	}
}

func TestServiceFlagConflicts(t *testing.T) {
	code, _, stderr := runCLI(t, "", "-s", "redis", "-d", "db:6379")
	if code != ExitUsage || !strings.Contains(stderr, "--detect-only") {
		t.Errorf("exit code = %d, stderr = %q", code, stderr)
	}
	code, _, stderr = runCLI(t, "", "-s", "gopher", "db:70")
	if code != ExitUsage || !strings.Contains(stderr, "use one of") {
		t.Errorf("exit code = %d, stderr = %q", code, stderr)
	}
}
