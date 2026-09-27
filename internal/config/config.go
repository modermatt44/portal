// Package config loads portal's optional configuration file, which sets
// preferred clients, per-host overrides and detection timeouts.
//
// Example:
//
//	[clients]
//	postgresql = "pgcli"
//	redis = "redis-cli -n 2 -h {host} -p {port}"
//
//	[detect]
//	timeout = "5s"
//
//	[hosts."cache.local:6380"]
//	service = "redis"
//
//	[hosts."*:2222"]
//	service = "ssh"
package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/modermatt44/portal/internal/detect"
	"github.com/modermatt44/portal/internal/target"
)

// EnvPath is the environment variable that overrides the config location.
const EnvPath = "PORTAL_CONFIG"

// Config is the parsed configuration. The zero value is an empty
// configuration.
type Config struct {
	// Path is the file the configuration was loaded from, or "" if none.
	Path string
	// Clients maps a service to the preferred client command line.
	Clients map[detect.Service]string
	// Hosts holds per-endpoint overrides, keyed by normalized "host:port"
	// or "*:port".
	Hosts map[string]Host
	// Timeout, BannerTimeout, TLSTimeout and ProbeTimeout override the
	// detection timeouts when non-zero.
	Timeout       time.Duration
	BannerTimeout time.Duration
	TLSTimeout    time.Duration
	ProbeTimeout  time.Duration
}

// Host overrides detection or the client for one endpoint.
type Host struct {
	// Service, if set, skips detection: it is a service name such as
	// "redis", or "raw"/"tls" for portal's raw session.
	Service string
	// Client, if set, is the client command line for this endpoint.
	Client string
}

// DefaultPath returns where portal looks for its config file: $PORTAL_CONFIG
// if set; otherwise %AppData%\portal\config.toml on Windows and
// $XDG_CONFIG_HOME/portal/config.toml or ~/.config/portal/config.toml
// elsewhere (including macOS, following command-line tool conventions).
func DefaultPath() string {
	if p := os.Getenv(EnvPath); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "portal", "config.toml")
		}
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "portal", "config.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "portal", "config.toml")
}

// Load reads the config file at path. If the file does not exist and
// mustExist is false, Load returns an empty configuration.
func Load(path string, mustExist bool) (*Config, error) {
	if path == "" {
		return &Config{}, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) && !mustExist {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// Parse reads a configuration from r. Unknown tables and keys are errors,
// so that typos do not go unnoticed.
func Parse(r io.Reader) (*Config, error) {
	tables, err := parseTOML(r)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Clients: map[detect.Service]string{}, Hosts: map[string]Host{}}
	for _, t := range tables {
		if err := cfg.apply(t); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func (c *Config) apply(t *table) error {
	name := strings.Join(t.path, ".")
	switch {
	case len(t.path) == 0:
		for k, e := range t.keys {
			return &SyntaxError{e.line, fmt.Sprintf("key %q must be inside a table such as [clients] or [detect]", k)}
		}
	case name == "clients":
		for k, e := range t.keys {
			svc, ok := detect.ParseService(k)
			if !ok {
				return &SyntaxError{e.line, fmt.Sprintf("unknown service %q in [clients]; use one of: %s", k, serviceList())}
			}
			if _, dup := c.Clients[svc]; dup {
				return &SyntaxError{e.line, fmt.Sprintf("client for %s is set twice in [clients] (%q is an alias)", svc, k)}
			}
			s, err := stringValue(k, e)
			if err != nil {
				return err
			}
			c.Clients[svc] = s
		}
	case name == "detect":
		fields := map[string]*time.Duration{
			"timeout":        &c.Timeout,
			"banner_timeout": &c.BannerTimeout,
			"tls_timeout":    &c.TLSTimeout,
			"probe_timeout":  &c.ProbeTimeout,
		}
		for k, e := range t.keys {
			dst, ok := fields[k]
			if !ok {
				return &SyntaxError{e.line, fmt.Sprintf("unknown key %q in [detect]; use timeout, banner_timeout, tls_timeout or probe_timeout", k)}
			}
			s, err := stringValue(k, e)
			if err != nil {
				return err
			}
			d, err := time.ParseDuration(s)
			if err != nil || d <= 0 {
				return &SyntaxError{e.line, fmt.Sprintf("%s = %q is not a positive duration; use e.g. \"5s\" or \"500ms\"", k, s)}
			}
			*dst = d
		}
	case len(t.path) == 2 && t.path[0] == "hosts":
		key, err := normalizeHostKey(t.path[1])
		if err != nil {
			return &SyntaxError{t.line, err.Error()}
		}
		var h Host
		for k, e := range t.keys {
			s, err := stringValue(k, e)
			if err != nil {
				return err
			}
			switch k {
			case "service":
				if _, ok := detect.ParseService(s); !ok && s != "raw" && s != "tls" {
					return &SyntaxError{e.line, fmt.Sprintf("unknown service %q; use one of: %s, raw, tls", s, serviceList())}
				}
				h.Service = s
			case "client":
				h.Client = s
			default:
				return &SyntaxError{e.line, fmt.Sprintf("unknown key %q in [hosts.%q]; use service or client", k, t.path[1])}
			}
		}
		c.Hosts[key] = h
	default:
		return &SyntaxError{t.line, fmt.Sprintf("unknown table [%s]; use [clients], [detect] or [hosts.\"host:port\"]", name)}
	}
	return nil
}

// Host returns the override for t: an exact "host:port" entry first, then
// a "*:port" entry.
func (c *Config) Host(t target.Target) (Host, bool) {
	if h, ok := c.Hosts[strings.ToLower(t.Addr())]; ok {
		return h, true
	}
	h, ok := c.Hosts["*:"+strconv.Itoa(t.Port)]
	return h, ok
}

// Client returns the preferred client command line for service at t,
// taking per-host overrides into account.
func (c *Config) Client(t target.Target, service detect.Service) string {
	if h, ok := c.Host(t); ok && h.Client != "" {
		return h.Client
	}
	return c.Clients[service]
}

// normalizeHostKey validates a [hosts."..."] key and returns it in the
// form used for lookups.
func normalizeHostKey(key string) (string, error) {
	if port, ok := strings.CutPrefix(key, "*:"); ok {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid port in [hosts.%q]", key)
		}
		return "*:" + strconv.Itoa(n), nil
	}
	t, err := target.Parse([]string{key})
	if err != nil {
		return "", fmt.Errorf("invalid host in [hosts.%q]: %v", key, err)
	}
	return strings.ToLower(t.Addr()), nil
}

func stringValue(key string, e entry) (string, error) {
	s, ok := e.value.(string)
	if !ok {
		return "", &SyntaxError{e.line, fmt.Sprintf("%s must be a quoted string", key)}
	}
	return s, nil
}

func serviceList() string {
	var names []string
	for _, s := range detect.Services() {
		names = append(names, string(s))
	}
	return strings.Join(names, ", ")
}
