package target

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    Target
		wantErr string // substring of the error; empty means success
	}{
		{name: "host:port", args: []string{"db.local:5432"}, want: Target{"db.local", 5432}},
		{name: "ipv4", args: []string{"10.0.0.5:6379"}, want: Target{"10.0.0.5", 6379}},
		{name: "ipv6 brackets", args: []string{"[::1]:22"}, want: Target{"::1", 22}},
		{name: "ipv6 zone", args: []string{"[fe80::1%eth0]:22"}, want: Target{"fe80::1%eth0", 22}},
		{name: "host port", args: []string{"server", "22"}, want: Target{"server", 22}},
		{name: "ipv6 host port", args: []string{"::1", "22"}, want: Target{"::1", 22}},
		{name: "bracketed ipv6 host port", args: []string{"[::1]", "22"}, want: Target{"::1", 22}},
		{name: "url with default port", args: []string{"https://example.com"}, want: Target{"example.com", 443}},
		{name: "url with path", args: []string{"http://example.com/index.html"}, want: Target{"example.com", 80}},
		{name: "url with port", args: []string{"postgres://db:6543/app"}, want: Target{"db", 6543}},
		{name: "url ipv6", args: []string{"http://[::1]:8080"}, want: Target{"::1", 8080}},

		{name: "no args", args: nil, wantErr: "missing target"},
		{name: "missing port", args: []string{"db.local"}, wantErr: "missing port"},
		{name: "empty port", args: []string{"db.local:"}, wantErr: "missing port"},
		{name: "missing host", args: []string{":22"}, wantErr: "missing host"},
		{name: "bare ipv6", args: []string{"::1"}, wantErr: "IPv6"},
		{name: "bracketed ipv6 no port", args: []string{"[::1]"}, wantErr: "missing port"},
		{name: "port not a number", args: []string{"db:abc"}, wantErr: "invalid port"},
		{name: "port zero", args: []string{"db:0"}, wantErr: "invalid port"},
		{name: "port too big", args: []string{"db", "65536"}, wantErr: "invalid port"},
		{name: "too many args", args: []string{"db", "5432", "-U"}, wantErr: "after --"},
		{name: "unknown scheme", args: []string{"gopher://example.com"}, wantErr: "default port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Parse(%q) error = %v, want error containing %q", tt.args, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.args, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.args, got, tt.want)
			}
		})
	}
}

func TestTargetAddr(t *testing.T) {
	tests := []struct {
		t    Target
		want string
		ip   bool
	}{
		{Target{"db.local", 5432}, "db.local:5432", false},
		{Target{"::1", 22}, "[::1]:22", true},
		{Target{"10.0.0.5", 6379}, "10.0.0.5:6379", true},
	}
	for _, tt := range tests {
		if got := tt.t.Addr(); got != tt.want {
			t.Errorf("%+v.Addr() = %q, want %q", tt.t, got, tt.want)
		}
		if got := tt.t.IsIP(); got != tt.ip {
			t.Errorf("%+v.IsIP() = %v, want %v", tt.t, got, tt.ip)
		}
	}
}
