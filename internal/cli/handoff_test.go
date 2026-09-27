package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
	"github.com/modermatt44/portal/internal/term"
)

func sshServer(t *testing.T) *fakeserver.Server {
	return fakeserver.Start(t, fakeserver.Lines("SSH-2.0-OpenSSH_9.6p1\r\n", nil))
}

// writeConfig writes a config file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDryRun(t *testing.T) {
	s := sshServer(t)
	host, port := s.Target.Host, s.Target.Port
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"detected", []string{"-n", s.Target.String()}, fmt.Sprintf("ssh -p %d %s\n", port, host)},
		{"host port form", []string{"-n", host, fmt.Sprint(port)}, fmt.Sprintf("ssh -p %d %s\n", port, host)},
		{"passthrough", []string{"-n", s.Target.String(), "--", "-l", "admin", "uptime"}, fmt.Sprintf("ssh -p %d %s -l admin uptime\n", port, host)},
		{"service flag", []string{"-n", "-s", "postgres", s.Target.String(), "--", "-U", "admin"}, fmt.Sprintf("psql -h %s -p %d -U admin\n", host, port)},
		{"service raw", []string{"-n", "-s", "raw", s.Target.String()}, "(built-in raw TCP session)\n"},
		{"service https", []string{"-n", "-s", "https", s.Target.String()}, fmt.Sprintf("curl -v https://%s\n", s.Target)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, "", tt.args...)
			if code != ExitOK {
				t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
			}
			if stdout != tt.want {
				t.Errorf("stdout = %q, want %q", stdout, tt.want)
			}
		})
	}
}

func TestServiceFlagSkipsDetection(t *testing.T) {
	// Nothing listens on the port, so this only works without detection.
	code, stdout, stderr := runCLI(t, "", "-n", "-s", "redis", closedPort(t))
	if code != ExitOK || !strings.HasPrefix(stdout, "redis-cli -h 127.0.0.1 -p ") {
		t.Errorf("exit code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestMissingClientWithoutTTY(t *testing.T) {
	s := sshServer(t)
	code, stdout, stderr := runCLIWith(t, cliEnv{installed: []string{}}, "", s.Target.String())
	if code != ExitNoClient {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, ExitNoClient, stderr)
	}
	for _, want := range []string{"✓ SSH (OpenSSH 9.6p1) detected on " + s.Target.String(), "ssh is not installed", "install it: sudo apt install openssh-client", "--service raw"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want %q", stderr, want)
		}
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
}

func TestMissingClientDryRun(t *testing.T) {
	s := sshServer(t)
	code, stdout, stderr := runCLIWith(t, cliEnv{installed: []string{}}, "", "-n", s.Target.String())
	if code != ExitNoClient {
		t.Fatalf("exit code = %d, want %d", code, ExitNoClient)
	}
	if !strings.HasPrefix(stdout, "ssh -p ") || !strings.Contains(stderr, "not installed") {
		t.Errorf("stdout = %q, stderr = %q", stdout, stderr)
	}
}

func TestMissingClientDeclineRaw(t *testing.T) {
	s := sshServer(t)
	code, _, stderr := runCLIWith(t, cliEnv{tty: true, installed: []string{}}, "n\n", s.Target.String())
	if code != ExitNoClient {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, ExitNoClient, stderr)
	}
	if !strings.Contains(stderr, "Open a raw TCP session instead? [Y/n]") {
		t.Errorf("stderr = %q, want the raw-session offer", stderr)
	}
	if strings.Count(stderr, "not installed") != 1 {
		t.Errorf("the missing client should be reported once: %q", stderr)
	}
}

func TestMissingClientAcceptRaw(t *testing.T) {
	s := sshServer(t)
	code, stdout, stderr := runCLIWith(t, cliEnv{tty: true, installed: []string{}}, "\n", s.Target.String())
	if code != ExitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "SSH-2.0-OpenSSH_9.6p1") {
		t.Errorf("stdout = %q, want the raw session to show the banner", stdout)
	}
}

func TestDetectOnlyShowsClient(t *testing.T) {
	s := sshServer(t)
	_, stdout, _ := runCLI(t, "", "-d", s.Target.String())
	if want := fmt.Sprintf("client    ssh -p %d 127.0.0.1", s.Target.Port); !strings.Contains(stdout, want) {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}

	_, stdout, _ = runCLIWith(t, cliEnv{installed: []string{}}, "", "-d", s.Target.String())
	if !strings.Contains(stdout, "not installed") {
		t.Errorf("stdout = %q, want a not-installed note", stdout)
	}

	_, stdout, _ = runCLI(t, "", "--json", s.Target.String(), "--", "-v")
	var got struct {
		Client []string `json:"client"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if want := []string{"ssh", "-p", fmt.Sprint(s.Target.Port), "127.0.0.1", "-v"}; strings.Join(got.Client, " ") != strings.Join(want, " ") {
		t.Errorf("client = %q, want %q", got.Client, want)
	}
}

func TestConfigHostOverride(t *testing.T) {
	addr := closedPort(t) // detection would fail: the override must skip it
	cfg := writeConfig(t, fmt.Sprintf(`
[clients]
redis = "valkey-cli -h {host} -p {port} -n 2"

[hosts.%q]
service = "redis"
`, addr))
	code, stdout, stderr := runCLI(t, "", "-n", "--config", cfg, addr)
	if code != ExitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	host, port, _ := strings.Cut(addr, ":")
	if want := fmt.Sprintf("valkey-cli -h %s -p %s -n 2\n", host, port); stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestConfigPreferredClient(t *testing.T) {
	s := sshServer(t)
	cfg := writeConfig(t, "[clients]\nssh = \"mosh --ssh='ssh -p {port}' {host}\"\n")
	_, stdout, stderr := runCLI(t, "", "-n", "--config", cfg, s.Target.String())
	if want := fmt.Sprintf("mosh '--ssh=ssh -p %d' 127.0.0.1\n", s.Target.Port); stdout != want {
		t.Errorf("stdout = %q, want %q (stderr: %s)", stdout, want, stderr)
	}
}

func TestConfigErrors(t *testing.T) {
	code, _, stderr := runCLI(t, "", "--config", filepath.Join(t.TempDir(), "missing.toml"), "db:5432")
	if code != ExitUsage || !strings.Contains(stderr, "config:") {
		t.Errorf("missing explicit config: exit %d, stderr %q", code, stderr)
	}
	bad := writeConfig(t, "[clients]\nssh = mosh\n")
	code, _, stderr = runCLI(t, "", "--config", bad, "db:5432")
	if code != ExitUsage || !strings.Contains(stderr, "line 2") {
		t.Errorf("bad config: exit %d, stderr %q", code, stderr)
	}
}

func TestExitStatusIsSilent(t *testing.T) {
	var buf strings.Builder
	if code := report(&buf, term.Style{}, exitStatus(42)); code != 42 || buf.Len() != 0 {
		t.Errorf("report(exitStatus(42)) = %d, output %q", code, buf.String())
	}
}
