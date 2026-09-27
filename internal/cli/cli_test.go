package cli

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/term"
)

// runCLI executes portal with args and returns the exit code and output.
func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	streams := Streams{In: strings.NewReader(stdin), Out: &out, Err: &errOut}
	cmd := NewRootCommand("test", streams)
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
