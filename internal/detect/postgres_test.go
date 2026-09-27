package detect

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

// pgMessage builds a backend message.
func pgMessage(typ byte, body []byte) []byte {
	msg := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(msg[1:], uint32(4+len(body)))
	return append(msg, body...)
}

// pgHandler emulates PostgreSQL. ssl is the answer to SSLRequest ('S' or
// 'N'); reply is sent after the startup message.
func pgHandler(t *testing.T, ssl byte, reply []byte) func(net.Conn) {
	return func(conn net.Conn) {
		var req [8]byte
		if _, err := io.ReadFull(conn, req[:]); err != nil {
			return
		}
		if binary.BigEndian.Uint32(req[0:]) != 8 || binary.BigEndian.Uint32(req[4:]) != pgSSLRequestCode {
			return // not an SSLRequest: hang up like a real server would
		}
		conn.Write([]byte{ssl})
		if ssl == 'S' {
			tc := tls.Server(conn, fakeserver.TLSConfig(t))
			if tc.Handshake() != nil {
				return
			}
			conn = tc
		}
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		startup := make([]byte, binary.BigEndian.Uint32(hdr[:])-4)
		if _, err := io.ReadFull(conn, startup); err != nil {
			return
		}
		if binary.BigEndian.Uint32(startup) != pgProtocol3 {
			t.Errorf("startup protocol = %d", binary.BigEndian.Uint32(startup))
		}
		conn.Write(reply)
		io.Copy(io.Discard, conn)
	}
}

func TestDetectPostgreSQL(t *testing.T) {
	t.Parallel()
	sasl := pgMessage('R', append([]byte{0, 0, 0, 10}, "SCRAM-SHA-256\x00\x00"...))
	trust := append(pgMessage('R', []byte{0, 0, 0, 0}),
		pgMessage('S', []byte("server_version\x0016.2 (Debian 16.2-1.pgdg120+2)\x00"))...)
	trust = append(trust, pgMessage('Z', []byte{'I'})...)
	noRole := pgMessage('E', []byte("SFATAL\x00C28000\x00Mrole \"portal\" does not exist\x00\x00"))

	tests := []struct {
		name        string
		ssl         byte
		reply       []byte
		wantVersion string
		wantDetails map[string]string
		wantTLS     bool
	}{
		{"scram", 'N', sasl, "", map[string]string{"ssl": "not supported", "auth": "SASL (SCRAM-SHA-256)"}, false},
		{"trust", 'N', trust, "16.2", map[string]string{"auth": "none (trust)"}, false},
		{"error", 'N', noRole, "", map[string]string{"server_says": `role "portal" does not exist`}, false},
		{"ssl", 'S', sasl, "", map[string]string{"ssl": "supported", "auth": "SASL (SCRAM-SHA-256)"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := fakeserver.Start(t, pgHandler(t, tt.ssl, tt.reply))
			best := wantBest(t, detectFake(t, s), PostgreSQL, Confirmed)
			if best.Version != tt.wantVersion {
				t.Errorf("version = %q, want %q", best.Version, tt.wantVersion)
			}
			for k, v := range tt.wantDetails {
				if best.Details[k] != v {
					t.Errorf("detail %s = %q, want %q", k, best.Details[k], v)
				}
			}
			if tt.wantTLS != (best.TLS != nil && best.StartTLS) {
				t.Errorf("TLS = %+v, StartTLS = %v; want TLS upgrade = %v", best.TLS, best.StartTLS, tt.wantTLS)
			}
		})
	}
}
