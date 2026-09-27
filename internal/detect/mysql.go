package detect

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"unicode"
)

func init() { Register(mysqlProber{}) }

// mysqlProber recognizes MySQL and MariaDB by the initial handshake packet
// the server sends on connect.
type mysqlProber struct{}

func (mysqlProber) Name() string     { return "mysql" }
func (mysqlProber) Service() Service { return MySQL }

// MatchBanner parses the first packet: a 3-byte little-endian length, a
// sequence number of 0, and a payload that is either a protocol-10
// handshake or an error packet (e.g. "Host is not allowed to connect").
func (mysqlProber) MatchBanner(banner []byte) *Result {
	if len(banner) < 5 || banner[3] != 0 {
		return nil
	}
	n := int(banner[0]) | int(banner[1])<<8 | int(banner[2])<<16
	if n < 2 || n > 1<<16 {
		return nil
	}
	payload := banner[4:]
	if len(payload) > n {
		payload = payload[:n]
	}
	switch payload[0] {
	case 0x0a:
		return parseMySQLHandshake(payload[1:])
	case 0xff:
		return parseMySQLError(payload[1:])
	}
	return nil
}

func parseMySQLHandshake(p []byte) *Result {
	end := bytes.IndexByte(p, 0)
	if end <= 0 || end > 64 {
		return nil
	}
	raw := string(p[:end])
	for _, r := range raw {
		if !unicode.IsPrint(r) {
			return nil
		}
	}
	r := &Result{
		Service:    MySQL,
		Confidence: Confirmed,
		Evidence:   "handshake packet, server version " + strconv.Quote(raw),
	}
	// MariaDB prefixes its version with "5.5.5-" for old clients.
	v := strings.TrimPrefix(raw, "5.5.5-")
	if strings.Contains(v, "MariaDB") {
		r.Product = "MariaDB"
	} else {
		r.Product = "MySQL"
	}
	r.Version, _, _ = strings.Cut(v, "-")
	if plugin := mysqlAuthPlugin(p[end+1:]); plugin != "" {
		r.setDetail("auth_plugin", plugin)
	}
	return r
}

// mysqlAuthPlugin extracts the authentication plugin name that ends a
// protocol-10 handshake, after the server version.
func mysqlAuthPlugin(p []byte) string {
	// connection id (4), auth data part 1 (8), filler (1), capabilities (2),
	// charset (1), status (2), capabilities (2), auth data length (1),
	// reserved (10)
	const fixed = 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
	if len(p) < fixed {
		return ""
	}
	authLen := int(p[fixed-11])
	rest := p[fixed:]
	skip := max(13, authLen-8)
	if len(rest) <= skip {
		return ""
	}
	name, _, _ := bytes.Cut(rest[skip:], []byte{0})
	return string(name)
}

func parseMySQLError(p []byte) *Result {
	if len(p) < 3 {
		return nil
	}
	code := binary.LittleEndian.Uint16(p)
	msg := p[2:]
	if len(msg) > 0 && msg[0] == '#' && len(msg) >= 6 {
		msg = msg[6:] // SQL state marker and code
	}
	text := string(msg)
	if code < 1000 || code > 5000 || !isPrintable(text) {
		return nil
	}
	r := &Result{
		Service:    MySQL,
		Confidence: Confirmed,
		Evidence:   "error packet " + strconv.Itoa(int(code)) + " " + strconv.Quote(text),
	}
	if strings.Contains(text, "MariaDB") {
		r.Product = "MariaDB"
	}
	r.setDetail("server_says", text)
	return r
}

func isPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return s != ""
}
