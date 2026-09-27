package clients

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/detect"
	"github.com/modermatt44/portal/internal/target"
)

// fakeLookPath pretends that exactly the given programs are installed.
func fakeLookPath(installed ...string) func(string) (string, error) {
	return func(file string) (string, error) {
		for _, p := range installed {
			if p == file {
				return "/usr/bin/" + file, nil
			}
		}
		return "", exec.ErrNotFound
	}
}

// allInstalled pretends every program is installed.
func allInstalled(file string) (string, error) { return "/usr/bin/" + file, nil }

func TestResolveDefaults(t *testing.T) {
	db := target.Target{Host: "db.local", Port: 5432}
	tests := []struct {
		name string
		req  Request
		want string // Command.String()
	}{
		{"postgres", Request{Target: db, Service: detect.PostgreSQL}, "psql -h db.local -p 5432"},
		{"postgres passthrough", Request{Target: db, Service: detect.PostgreSQL, Extra: []string{"-U", "admin", "mydb"}}, "psql -h db.local -p 5432 -U admin mydb"},
		{"ssh", Request{Target: target.Target{Host: "server", Port: 22}, Service: detect.SSH}, "ssh -p 22 server"},
		{"ssh ipv6", Request{Target: target.Target{Host: "::1", Port: 2222}, Service: detect.SSH}, "ssh -p 2222 ::1"},
		{"https default port", Request{Target: target.Target{Host: "example.com", Port: 443}, Service: detect.HTTPS, TLS: true}, "curl -v https://example.com"},
		{"https other port", Request{Target: target.Target{Host: "example.com", Port: 8443}, Service: detect.HTTPS, TLS: true}, "curl -v https://example.com:8443"},
		{"http", Request{Target: target.Target{Host: "localhost", Port: 8080}, Service: detect.HTTP}, "curl -v http://localhost:8080"},
		{"http ipv6", Request{Target: target.Target{Host: "::1", Port: 80}, Service: detect.HTTP}, "curl -v 'http://[::1]'"},
		{"redis", Request{Target: target.Target{Host: "10.0.0.5", Port: 6379}, Service: detect.Redis}, "redis-cli -h 10.0.0.5 -p 6379"},
		{"redis tls", Request{Target: target.Target{Host: "cache", Port: 6380}, Service: detect.Redis, TLS: true}, "redis-cli -h cache -p 6380 --tls"},
		{"mysql", Request{Target: target.Target{Host: "localhost", Port: 3306}, Service: detect.MySQL}, "mysql -h localhost -P 3306 --protocol=TCP"},
		{"mongodb", Request{Target: target.Target{Host: "mongo", Port: 27017}, Service: detect.MongoDB}, "mongosh --host mongo --port 27017"},
		{"ftp", Request{Target: target.Target{Host: "files", Port: 2121}, Service: detect.FTP}, "lftp -p 2121 files"},
		{"smtp starttls", Request{Target: target.Target{Host: "mx.example.com", Port: 25}, Service: detect.SMTP, StartTLS: true}, "openssl s_client -starttls smtp -crlf -quiet -connect mx.example.com:25 -servername mx.example.com"},
		{"smtp plain", Request{Target: target.Target{Host: "mx", Port: 25}, Service: detect.SMTP}, "(built-in raw TCP session)"},
		{"imaps", Request{Target: target.Target{Host: "mail", Port: 993}, Service: detect.IMAP, TLS: true}, "(built-in raw TLS session)"},
		{"unknown", Request{Target: target.Target{Host: "h", Port: 1234}, Service: detect.Unknown}, "(built-in raw TCP session)"},
	}
	r := Resolver{LookPath: allInstalled}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := r.Resolve(tt.req)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got := cmd.String(); got != tt.want {
				t.Errorf("Resolve = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveFallsBackToAlternative(t *testing.T) {
	r := Resolver{LookPath: fakeLookPath("pgcli")}
	cmd, err := r.Resolve(Request{Target: target.Target{Host: "db", Port: 5432}, Service: detect.PostgreSQL})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "pgcli" || cmd.Path != "/usr/bin/pgcli" {
		t.Errorf("Resolve = %+v, want pgcli", cmd)
	}
}

func TestResolveMissing(t *testing.T) {
	r := Resolver{LookPath: fakeLookPath(), GOOS: "darwin"}
	cmd, err := r.Resolve(Request{Target: target.Target{Host: "db", Port: 5432}, Service: detect.PostgreSQL})
	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want *MissingError", err)
	}
	if got := missing.Error(); got != "psql is not installed (also looked for pgcli)" {
		t.Errorf("Error() = %q", got)
	}
	if !strings.Contains(missing.Hint, "brew install libpq") {
		t.Errorf("Hint = %q, want the macOS install hint", missing.Hint)
	}
	if cmd.String() != "psql -h db -p 5432" || cmd.Path != "" {
		t.Errorf("want the would-be command without a path, got %+v", cmd)
	}
}

func TestResolvePreferred(t *testing.T) {
	db := target.Target{Host: "db", Port: 5433}
	tests := []struct {
		name      string
		preferred string
		extra     []string
		want      string
	}{
		{"known program gets its arguments", "pgcli", nil, "pgcli -h db -p 5433"},
		{"template", "usql pg://{host}:{port}/app", []string{"-c", "select 1"}, "usql pg://db:5433/app -c 'select 1'"},
		{"quoted template", `mytool --target "{addr}" --name 'a b'`, nil, "mytool --target db:5433 --name 'a b'"},
		{"program without placeholders", "mytool --flag", nil, "mytool --flag"},
	}
	r := Resolver{LookPath: allInstalled}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := r.Resolve(Request{Target: db, Service: detect.PostgreSQL, Preferred: tt.preferred, Extra: tt.extra})
			if err != nil {
				t.Fatal(err)
			}
			if got := cmd.String(); got != tt.want {
				t.Errorf("Resolve = %q, want %q", got, tt.want)
			}
		})
	}

	_, err := Resolver{LookPath: fakeLookPath()}.Resolve(Request{Target: db, Service: detect.PostgreSQL, Preferred: "usql x"})
	var missing *MissingError
	if !errors.As(err, &missing) || !strings.Contains(missing.Hint, "config") {
		t.Errorf("missing preferred client: err = %v", err)
	}
}

func TestSplitWords(t *testing.T) {
	tests := []struct {
		in   string
		want []string
		err  bool
	}{
		{"a b  c", []string{"a", "b", "c"}, false},
		{`a "b c" 'd e'`, []string{"a", "b c", "d e"}, false},
		{`a\ b`, []string{"a b"}, false},
		{`"" x`, []string{"", "x"}, false},
		{`"unterminated`, nil, true},
	}
	for _, tt := range tests {
		got, err := splitWords(tt.in)
		if (err != nil) != tt.err || strings.Join(got, "|") != strings.Join(tt.want, "|") {
			t.Errorf("splitWords(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestEveryServiceHasAClient(t *testing.T) {
	for _, s := range append(detect.Services(), detect.Unknown) {
		if len(registry[s]) == 0 {
			t.Errorf("no client registered for %s", s)
		}
		for _, c := range registry[s] {
			if !c.Builtin && c.When == nil && c.InstallHint("linux") == "" {
				t.Errorf("%s client %s has no install hint", s, c.Program)
			}
		}
	}
}
