// Package target parses the host and port that portal should connect to.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Target is a TCP endpoint to probe and connect to.
type Target struct {
	// Host is a hostname or IP address, without brackets.
	Host string
	// Port is the TCP port, between 1 and 65535.
	Port int
}

// Addr returns the target in the form accepted by net.Dial,
// e.g. "db.local:5432" or "[::1]:22".
func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// String implements fmt.Stringer and returns the same value as Addr.
func (t Target) String() string { return t.Addr() }

// IsIP reports whether Host is a literal IP address rather than a name.
func (t Target) IsIP() bool {
	_, err := netip.ParseAddr(t.Host)
	return err == nil
}

// schemePorts maps URL schemes to the port they imply when a URL is given
// without an explicit port.
var schemePorts = map[string]int{
	"ftp":        21,
	"ssh":        22,
	"smtp":       25,
	"http":       80,
	"pop3":       110,
	"imap":       143,
	"https":      443,
	"smtps":      465,
	"imaps":      993,
	"pop3s":      995,
	"mysql":      3306,
	"postgres":   5432,
	"postgresql": 5432,
	"redis":      6379,
	"rediss":     6379,
	"mongodb":    27017,
}

// Parse builds a Target from command-line arguments. It accepts a single
// "host:port" or "[ipv6]:port" argument, a URL such as "https://example.com",
// or two arguments "host" "port".
//
// The returned errors are meant to be shown to the user as is: they say what
// is wrong and how to fix it.
func Parse(args []string) (Target, error) {
	switch len(args) {
	case 0:
		return Target{}, errors.New("missing target; try: portal db.local:5432")
	case 1:
		return parseOne(args[0])
	case 2:
		host := strings.TrimSuffix(strings.TrimPrefix(args[0], "["), "]")
		return build(host, args[1], args[0])
	default:
		return Target{}, fmt.Errorf("too many arguments (%s); to pass options to the client, put them after --, e.g.: portal %s -- -U admin",
			strings.Join(args, " "), args[0])
	}
}

func parseOne(s string) (Target, error) {
	if strings.Contains(s, "://") {
		return parseURL(s)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		switch {
		case strings.Count(s, ":") > 1 && !strings.HasPrefix(s, "["):
			return Target{}, fmt.Errorf("%q looks like an IPv6 address; put it in brackets and add a port, e.g. [%s]:22, or pass the port separately: portal %s 22", s, s, s)
		case !strings.Contains(s, ":") || strings.HasPrefix(s, "["):
			return Target{}, fmt.Errorf("missing port in %q; add one, e.g. %s:22, or pass it separately: portal %s 22", s, s, s)
		default:
			return Target{}, fmt.Errorf("cannot parse %q as host:port: %v", s, err)
		}
	}
	return build(host, port, s)
}

func parseURL(s string) (Target, error) {
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return Target{}, fmt.Errorf("cannot parse %q as a URL; pass host and port instead, e.g. example.com:443", s)
	}
	if p := u.Port(); p != "" {
		return build(u.Hostname(), p, s)
	}
	port, ok := schemePorts[strings.ToLower(u.Scheme)]
	if !ok {
		return Target{}, fmt.Errorf("don't know the default port for %q URLs; add one, e.g. %s://%s:PORT", u.Scheme, u.Scheme, u.Hostname())
	}
	return Target{Host: u.Hostname(), Port: port}, nil
}

func build(host, port, input string) (Target, error) {
	if host == "" {
		return Target{}, fmt.Errorf("missing host in %q; e.g. localhost:%s", input, port)
	}
	if port == "" {
		return Target{}, fmt.Errorf("missing port in %q; add one, e.g. %s:22", input, host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return Target{}, fmt.Errorf("invalid port %q: must be a number between 1 and 65535", port)
	}
	return Target{Host: host, Port: n}, nil
}
