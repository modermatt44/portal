package detect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/modermatt44/portal/internal/target"
)

func init() { Register(redisProber{}) }

// redisProber sends a RESP PING and, if allowed, INFO server. It also
// identifies Redis-compatible servers such as Valkey and KeyDB.
type redisProber struct{}

func (redisProber) Name() string     { return "redis" }
func (redisProber) Service() Service { return Redis }

// Probe sends PING as a RESP array. "+PONG" confirms Redis, as do the
// errors Redis returns before authentication (-NOAUTH) or in protected
// mode (-DENIED). Any other RESP error is only Likely.
func (redisProber) Probe(ctx context.Context, conn net.Conn, t target.Target) (*Result, error) {
	if _, err := io.WriteString(conn, "*1\r\n$4\r\nPING\r\n"); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	line, err := readRESPLine(br)
	if err != nil {
		return nil, err
	}
	r := &Result{Service: Redis, Confidence: Confirmed, Evidence: "answered PING with " + strconv.Quote(line)}
	switch {
	case line == "+PONG":
		readRedisInfo(conn, br, r)
	case strings.HasPrefix(line, "-NOAUTH"), strings.HasPrefix(line, "-WRONGPASS"):
		r.setDetail("auth", "required")
	case strings.HasPrefix(line, "-DENIED"):
		r.setDetail("protected_mode", "enabled; only local clients may connect")
	case strings.HasPrefix(line, "-"):
		r.Confidence = Likely
	default:
		return nil, nil
	}
	return r, nil
}

// readRedisInfo asks for "INFO server" and records the product and version.
// Failures are ignored: PONG already confirmed the service.
func readRedisInfo(conn net.Conn, br *bufio.Reader, r *Result) {
	if _, err := io.WriteString(conn, "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"); err != nil {
		return
	}
	header, err := readRESPLine(br)
	if err != nil || !strings.HasPrefix(header, "$") {
		return
	}
	n, err := strconv.Atoi(header[1:])
	if err != nil || n <= 0 || n > 64<<10 {
		return
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return
	}
	info := map[string]string{}
	for _, l := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), ":"); ok {
			info[k] = v
		}
	}
	switch {
	case info["valkey_version"] != "":
		r.Product, r.Version = "Valkey", info["valkey_version"]
	case info["redis_version"] != "":
		r.Product, r.Version = "Redis", info["redis_version"]
	}
	if m := info["redis_mode"]; m != "" {
		r.setDetail("mode", m)
	}
	if os := info["os"]; os != "" {
		r.setDetail("os", os)
	}
}

// readRESPLine reads one CRLF-terminated RESP line of at most 512 bytes.
func readRESPLine(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for sb.Len() < 512 {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return strings.TrimSuffix(sb.String(), "\r"), nil
		}
		sb.WriteByte(b)
	}
	return "", fmt.Errorf("line too long")
}
