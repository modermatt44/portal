package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/clients"
	"github.com/modermatt44/portal/internal/config"
	"github.com/modermatt44/portal/internal/fakeserver"
	"github.com/modermatt44/portal/internal/term"
)

// runCLI executes portal with args, as if every client program were
// installed, and returns the exit code and output.
func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return runCLIWith(t, cliEnv{}, stdin, args...)
}

// cliEnv describes the environment a test runs portal in.
type cliEnv struct {
	// tty makes stdin count as an interactive terminal.
	tty bool
	// installed lists the client programs on PATH; nil means all of them.
	installed []string
}

// runCLIWith is like runCLI with a custom environment. The user's real
// config file is never read.
func runCLIWith(t *testing.T, env cliEnv, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "no-config.toml"))
	lookPath := func(file string) (string, error) {
		if env.installed == nil || slices.Contains(env.installed, file) {
			return "/usr/bin/" + file, nil
		}
		return "", exec.ErrNotFound
	}
	var out, errOut bytes.Buffer
	streams := Streams{In: strings.NewReader(stdin), Out: &out, Err: &errOut, InTTY: env.tty}
	cmd := newRootCommand("test", streams, clients.Resolver{LookPath: lookPath, GOOS: "linux"})
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	code = report(&errOut, term.Style{}, err)
	return code, out.String(), errOut.String()
}

// closedPort returns an address on 127.0.0.1 where nothing listens.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no target", nil, "missing target"},
		{"missing port", []string{"db.local"}, "missing port"},
		{"bad flag", []string{"--bogus", "db:1"}, "unknown flag"},
		{"client flag without dash", []string{"db:5432", "-U", "admin"}, "after --"},
		{"too many args", []string{"db", "5432", "extra"}, "after --"},
		{"bad timeout", []string{"--timeout", "0s", "db:1"}, "invalid --timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, "", tt.args...)
			if code != ExitUsage {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, ExitUsage, stderr)
			}
			if !strings.Contains(stderr, tt.want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.want)
			}
		})
	}
}

func TestConnectionRefused(t *testing.T) {
	code, _, stderr := runCLI(t, "", "-d", closedPort(t))
	if code != ExitConnection {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, ExitConnection, stderr)
	}
	if !strings.Contains(stderr, "cannot connect") || !strings.Contains(stderr, "→") {
		t.Errorf("stderr = %q, want an error and a hint", stderr)
	}
}

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		args        []string
		dash        int
		wantTarget  []string
		wantPassthr []string
	}{
		{[]string{"db:5432"}, -1, []string{"db:5432"}, nil},
		{[]string{"db:5432", "-U", "admin"}, 1, []string{"db:5432"}, []string{"-U", "admin"}},
		{[]string{"db", "5432", "mydb"}, 2, []string{"db", "5432"}, []string{"mydb"}},
		{[]string{"db:5432"}, 1, []string{"db:5432"}, []string{}},
	}
	for _, tt := range tests {
		gotT, gotE := splitArgs(tt.args, tt.dash)
		if strings.Join(gotT, " ") != strings.Join(tt.wantTarget, " ") || strings.Join(gotE, " ") != strings.Join(tt.wantPassthr, " ") {
			t.Errorf("splitArgs(%q, %d) = %q, %q; want %q, %q", tt.args, tt.dash, gotT, gotE, tt.wantTarget, tt.wantPassthr)
		}
	}
}

func TestDetectOnlyText(t *testing.T) {
	s := fakeserver.Start(t, fakeserver.Lines("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n", nil))
	code, stdout, stderr := runCLI(t, "", "-d", "--timeout", "3s", s.Target.String())
	if code != ExitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{"✓ SSH (OpenSSH 9.6p1) on " + s.Target.String(), "confirmed", "protocol"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want it to contain %q", stdout, want)
		}
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Error("stdout contains color codes although color is off")
	}
}

func TestDetectOnlyJSON(t *testing.T) {
	s := fakeserver.Start(t, fakeserver.Lines("SSH-2.0-OpenSSH_9.6p1\r\n", nil))
	code, stdout, stderr := runCLI(t, "", "--json", s.Target.String())
	if code != ExitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	var got struct {
		Service    string `json:"service"`
		Port       int    `json:"port"`
		Ambiguous  bool   `json:"ambiguous"`
		Candidates []struct {
			Confidence string `json:"confidence"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout, err)
	}
	if got.Service != "ssh" || got.Port != s.Target.Port || got.Ambiguous || len(got.Candidates) != 1 || got.Candidates[0].Confidence != "confirmed" {
		t.Errorf("JSON = %+v", got)
	}
}

func TestVerboseLogsToStderr(t *testing.T) {
	s := fakeserver.Start(t, fakeserver.Lines("SSH-2.0-OpenSSH_9.6p1\r\n", nil))
	_, stdout, stderr := runCLI(t, "", "-d", "-v", s.Target.String())
	if !strings.Contains(stderr, "banner") || strings.Contains(stdout, "banner \"SSH") {
		t.Errorf("verbose output should go to stderr only; stdout=%q stderr=%q", stdout, stderr)
	}
}
