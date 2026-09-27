package detect

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

// mysqlPacket frames payload as the first server packet (sequence 0).
func mysqlPacket(payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), 0}, payload...)
}

// mysqlHandshake builds a protocol-10 handshake for version and plugin.
func mysqlHandshake(version, plugin string) []byte {
	var p bytes.Buffer
	p.WriteByte(0x0a)
	p.WriteString(version + "\x00")
	p.Write([]byte{1, 0, 0, 0})       // connection id
	p.WriteString("abcdefgh")         // auth data part 1
	p.WriteByte(0)                    // filler
	p.Write([]byte{0xff, 0xf7})       // capabilities (low)
	p.WriteByte(0x21)                 // charset
	p.Write([]byte{0x02, 0x00})       // status
	p.Write([]byte{0xff, 0xdf})       // capabilities (high)
	p.WriteByte(21)                   // auth data length
	p.Write(make([]byte, 10))         // reserved
	p.WriteString("ijklmnopqrst\x00") // auth data part 2 (13 bytes)
	p.WriteString(plugin + "\x00")    // auth plugin
	return mysqlPacket(p.Bytes())
}

func TestMySQLMatchBanner(t *testing.T) {
	denied := mysqlPacket(append([]byte{0xff, 0x6a, 0x04}, "Host '10.0.0.9' is not allowed to connect to this MySQL server"...))
	tests := []struct {
		name        string
		banner      []byte
		wantMatch   bool
		wantProduct string
		wantVersion string
		wantPlugin  string
	}{
		{"mysql 8", mysqlHandshake("8.0.36", "caching_sha2_password"), true, "MySQL", "8.0.36", "caching_sha2_password"},
		{"mysql with suffix", mysqlHandshake("8.0.36-0ubuntu0.22.04.1", "caching_sha2_password"), true, "MySQL", "8.0.36", "caching_sha2_password"},
		{"mariadb", mysqlHandshake("5.5.5-10.11.6-MariaDB-0ubuntu0.24.04.1", "mysql_native_password"), true, "MariaDB", "10.11.6", "mysql_native_password"},
		{"host denied", denied, true, "", "", ""},
		{"ssh banner", []byte("SSH-2.0-OpenSSH_9.6\r\n"), false, "", "", ""},
		{"text", []byte("hello world\r\n"), false, "", "", ""},
		{"too short", []byte{1, 0, 0, 0}, false, "", "", ""},
		{"binary junk", mysqlPacket([]byte{0x0a, 0x01, 0x02, 0x00}), false, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mysqlProber{}.MatchBanner(tt.banner)
			if (r != nil) != tt.wantMatch {
				t.Fatalf("matched = %v, want %v (%+v)", r != nil, tt.wantMatch, r)
			}
			if r == nil {
				return
			}
			if r.Product != tt.wantProduct || r.Version != tt.wantVersion || r.Details["auth_plugin"] != tt.wantPlugin {
				t.Errorf("got %q %q plugin %q, want %q %q plugin %q", r.Product, r.Version, r.Details["auth_plugin"], tt.wantProduct, tt.wantVersion, tt.wantPlugin)
			}
		})
	}
}

func TestDetectMySQL(t *testing.T) {
	t.Parallel()
	s := fakeserver.Start(t, func(conn net.Conn) {
		conn.Write(mysqlHandshake("5.5.5-10.11.6-MariaDB", "mysql_native_password"))
		io.Copy(io.Discard, conn)
	})
	best := wantBest(t, detectFake(t, s), MySQL, Confirmed)
	if got := best.Label(); got != "MySQL (MariaDB 10.11.6)" {
		t.Errorf("Label() = %q", got)
	}
}
