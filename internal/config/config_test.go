package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modermatt44/portal/internal/detect"
	"github.com/modermatt44/portal/internal/target"
)

const example = `
# portal configuration
[clients]
postgres = "pgcli"     # aliases work too
redis = 'redis-cli -n 2 -h {host} -p {port}'

[detect]
timeout = "5s"
banner_timeout = "500ms"

[hosts."cache.local:6380"]
service = "redis"
client = "valkey-cli -h {host} -p {port}"

[hosts."*:2222"]
service = "ssh"

[hosts."[::1]:5433"]
service = "postgres"
`

func TestParseExample(t *testing.T) {
	cfg, err := Parse(strings.NewReader(example))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Clients[detect.PostgreSQL]; got != "pgcli" {
		t.Errorf("postgresql client = %q", got)
	}
	if got := cfg.Clients[detect.Redis]; got != "redis-cli -n 2 -h {host} -p {port}" {
		t.Errorf("redis client = %q", got)
	}
	if cfg.Timeout != 5*time.Second || cfg.BannerTimeout != 500*time.Millisecond || cfg.TLSTimeout != 0 {
		t.Errorf("timeouts = %v %v %v", cfg.Timeout, cfg.BannerTimeout, cfg.TLSTimeout)
	}

	tests := []struct {
		t          target.Target
		service    string
		client     string
		found      bool
		wantClient string // Client(t, redis)
	}{
		{target.Target{Host: "cache.local", Port: 6380}, "redis", "valkey-cli -h {host} -p {port}", true, "valkey-cli -h {host} -p {port}"},
		{target.Target{Host: "CACHE.local", Port: 6380}, "redis", "valkey-cli -h {host} -p {port}", true, "valkey-cli -h {host} -p {port}"},
		{target.Target{Host: "anything", Port: 2222}, "ssh", "", true, "redis-cli -n 2 -h {host} -p {port}"},
		{target.Target{Host: "::1", Port: 5433}, "postgres", "", true, "redis-cli -n 2 -h {host} -p {port}"},
		{target.Target{Host: "cache.local", Port: 6379}, "", "", false, "redis-cli -n 2 -h {host} -p {port}"},
	}
	for _, tt := range tests {
		h, ok := cfg.Host(tt.t)
		if ok != tt.found || h.Service != tt.service || h.Client != tt.client {
			t.Errorf("Host(%v) = %+v, %v; want service %q client %q found %v", tt.t, h, ok, tt.service, tt.client, tt.found)
		}
		if got := cfg.Client(tt.t, detect.Redis); got != tt.wantClient {
			t.Errorf("Client(%v, redis) = %q, want %q", tt.t, got, tt.wantClient)
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"root key", `timeout = "5s"`, "line 1: key \"timeout\" must be inside a table"},
		{"unknown table", "[client]\n", "unknown table [client]"},
		{"unknown service", "[clients]\npostgre = \"psql\"", "line 2: unknown service \"postgre\""},
		{"unknown detect key", "[detect]\ntimout = \"1s\"", "unknown key \"timout\""},
		{"bad duration", "[detect]\ntimeout = \"5 seconds\"", "not a positive duration"},
		{"number for string", "[detect]\ntimeout = 5", "must be a quoted string"},
		{"unquoted string", "[clients]\nssh = ssh", "strings need quotes"},
		{"bad host key", "[hosts.\"nohost\"]\nservice = \"ssh\"", "missing port"},
		{"bad wildcard", "[hosts.\"*:http\"]\nservice = \"http\"", "invalid port"},
		{"bad host service", "[hosts.\"a:1\"]\nservice = \"gopher\"", "unknown service \"gopher\""},
		{"unknown host key", "[hosts.\"a:1\"]\nsvc = \"ssh\"", "unknown key \"svc\""},
		{"alias duplicate", "[clients]\npostgresql = \"a\"\npg = \"b\"", "set twice"},
		{"duplicate key", "[clients]\nssh = \"a\"\nssh = \"b\"", "line 3: key \"ssh\" is defined twice"},
		{"duplicate table", "[detect]\n[detect]", "defined twice"},
		{"array", "[clients]\nssh = [\"a\"]", "arrays and inline tables are not supported"},
		{"array of tables", "[[hosts]]", "not supported"},
		{"dotted key", "[clients]\na.b = \"x\"", "dotted keys are not supported"},
		{"unterminated", "[clients]\nssh = \"abc", "unterminated string"},
		{"trailing junk", "[clients]\nssh = \"a\" b", "unexpected \"b\""},
		{"bad escape", `[clients]` + "\n" + `ssh = "C:\bin\ssh"`, "invalid escape"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.in))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Parse error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestParseStrings(t *testing.T) {
	cfg, err := Parse(strings.NewReader("[clients]\nssh = \"a \\\"b\\\" \\u00e9\\tc\"\n\"redis\" = 'C:\\tools\\redis-cli.exe' # literal\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Clients[detect.SSH]; got != "a \"b\" é\tc" {
		t.Errorf("basic string = %q", got)
	}
	if got := cfg.Clients[detect.Redis]; got != `C:\tools\redis-cli.exe` {
		t.Errorf("literal string = %q", got)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.toml")

	cfg, err := Load(missing, false)
	if err != nil || cfg.Path != "" {
		t.Errorf("Load(missing, optional) = %+v, %v; want empty config", cfg, err)
	}
	if _, err := Load(missing, true); err == nil {
		t.Error("Load(missing, required) succeeded")
	}

	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("[clients]\nssh = \"mosh\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, true)
	if err != nil || cfg.Path != path || cfg.Clients[detect.SSH] != "mosh" {
		t.Errorf("Load = %+v, %v", cfg, err)
	}

	if err := os.WriteFile(path, []byte("[clients]\nssh = \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, true); err == nil || !strings.Contains(err.Error(), path+": line 2") {
		t.Errorf("Load error = %v, want the path and line", err)
	}
}

func TestDefaultPathEnv(t *testing.T) {
	t.Setenv(EnvPath, "/tmp/custom.toml")
	if got := DefaultPath(); got != "/tmp/custom.toml" {
		t.Errorf("DefaultPath() = %q", got)
	}
}
