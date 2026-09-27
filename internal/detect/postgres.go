package detect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/modermatt44/portal/internal/target"
)

func init() { Register(postgresProber{}) }

// PostgreSQL wire protocol constants.
const (
	pgSSLRequestCode = 80877103
	pgProtocol3      = 196608 // 3.0
	pgProbeUser      = "portal"
)

// pgAuthMethods names the AuthenticationRequest codes.
var pgAuthMethods = map[uint32]string{
	0:  "none (trust)",
	2:  "Kerberos V5",
	3:  "cleartext password",
	5:  "MD5 password",
	7:  "GSSAPI",
	9:  "SSPI",
	10: "SASL",
}

// postgresProber sends an SSLRequest, then a startup message, to learn
// whether the server supports TLS and which authentication it asks for.
type postgresProber struct{}

func (postgresProber) Name() string     { return "postgresql" }
func (postgresProber) Service() Service { return PostgreSQL }

// Probe sends an SSLRequest. PostgreSQL answers with the single byte 'S'
// or 'N', which confirms the protocol. The probe then upgrades to TLS if
// offered and sends a startup message for user "portal" to report the
// authentication method. It never sends a password.
func (postgresProber) Probe(ctx context.Context, conn net.Conn, t target.Target) (*Result, error) {
	var req [8]byte
	binary.BigEndian.PutUint32(req[0:], 8)
	binary.BigEndian.PutUint32(req[4:], pgSSLRequestCode)
	if _, err := conn.Write(req[:]); err != nil {
		return nil, err
	}
	var answer [1]byte
	if _, err := io.ReadFull(conn, answer[:]); err != nil {
		return nil, err
	}
	r := &Result{Service: PostgreSQL, Confidence: Confirmed}
	switch answer[0] {
	case 'S':
		r.Evidence = "accepted SSLRequest ('S')"
		r.setDetail("ssl", "supported")
		tc := tls.Client(conn, clientTLSConfig(t, nil))
		if err := tc.HandshakeContext(ctx); err != nil {
			r.setDetail("ssl", "supported, but the handshake failed: "+err.Error())
			return r, nil
		}
		r.TLS = newTLSInfo(tc.ConnectionState(), t)
		r.StartTLS = true
		conn = tc
	case 'N':
		r.Evidence = "declined SSLRequest ('N')"
		r.setDetail("ssl", "not supported")
	default:
		return nil, nil
	}
	pgStartup(conn, r)
	return r, nil
}

// pgStartup sends a startup message and records what the server asks for.
// Failures are ignored: the SSLRequest answer already confirmed the service.
func pgStartup(conn net.Conn, r *Result) {
	var params bytes.Buffer
	for _, kv := range [][2]string{{"user", pgProbeUser}, {"database", pgProbeUser}, {"application_name", "portal"}} {
		params.WriteString(kv[0] + "\x00" + kv[1] + "\x00")
	}
	params.WriteByte(0)
	msg := make([]byte, 8, 8+params.Len())
	binary.BigEndian.PutUint32(msg[0:], uint32(8+params.Len()))
	binary.BigEndian.PutUint32(msg[4:], pgProtocol3)
	msg = append(msg, params.Bytes()...)
	if _, err := conn.Write(msg); err != nil {
		return
	}
	defer conn.Write([]byte{'X', 0, 0, 0, 4}) // Terminate

	for range 32 {
		typ, body, err := pgReadMessage(conn)
		if err != nil {
			return
		}
		switch typ {
		case 'R':
			if len(body) < 4 {
				return
			}
			code := binary.BigEndian.Uint32(body)
			method, ok := pgAuthMethods[code]
			if !ok {
				method = fmt.Sprintf("method %d", code)
			}
			if code == 10 {
				method += " (" + strings.Join(splitCStrings(body[4:]), ", ") + ")"
			}
			r.setDetail("auth", method)
			if code != 0 {
				return // the server wants credentials; stop here
			}
		case 'S':
			if kv := splitCStrings(body); len(kv) == 2 && kv[0] == "server_version" {
				r.Version, _, _ = strings.Cut(kv[1], " ")
			}
		case 'E':
			fields := pgErrorFields(body)
			r.setDetail("server_says", fields['M'])
			return
		case 'Z':
			return
		}
	}
}

// pgReadMessage reads one backend message: a type byte, a length, a body.
func pgReadMessage(conn net.Conn) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n < 4 || n > 64<<10 {
		return 0, nil, errors.New("implausible message length")
	}
	body := make([]byte, n-4)
	_, err := io.ReadFull(conn, body)
	return hdr[0], body, err
}

// pgErrorFields parses the fields of an ErrorResponse body.
func pgErrorFields(body []byte) map[byte]string {
	fields := map[byte]string{}
	for len(body) > 1 && body[0] != 0 {
		code := body[0]
		end := bytes.IndexByte(body[1:], 0)
		if end < 0 {
			break
		}
		fields[code] = string(body[1 : 1+end])
		body = body[2+end:]
	}
	return fields
}

// splitCStrings splits NUL-terminated strings, dropping empty ones.
func splitCStrings(b []byte) []string {
	var out []string
	for _, s := range bytes.Split(b, []byte{0}) {
		if len(s) > 0 {
			out = append(out, string(s))
		}
	}
	return out
}
