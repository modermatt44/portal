package detect

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/modermatt44/portal/internal/target"
)

func init() { Register(httpProber{}) }

// httpProber sends "GET /" and expects an HTTP/1.x status line. Inside TLS
// the engine reports the match as HTTPS.
type httpProber struct{}

func (httpProber) Name() string     { return "http" }
func (httpProber) Service() Service { return HTTP }

// Probe sends a minimal HTTP/1.1 request and reads the status line and
// headers of the response.
func (httpProber) Probe(ctx context.Context, conn net.Conn, t target.Target) (*Result, error) {
	host := t.Addr()
	if t.Port == 80 || t.Port == 443 {
		host = t.Host
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	_, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: portal\r\nAccept: */*\r\nConnection: close\r\n\r\n", host)
	if err != nil {
		return nil, err
	}
	tp := textproto.NewReader(bufio.NewReader(conn))
	status, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}
	proto, rest, _ := strings.Cut(status, " ")
	if !strings.HasPrefix(proto, "HTTP/1.") || len(rest) < 3 {
		return nil, nil
	}
	if _, err := strconv.Atoi(rest[:3]); err != nil {
		return nil, nil
	}
	header, _ := tp.ReadMIMEHeader() // a partial header is still useful

	r := &Result{
		Service:    HTTP,
		Product:    header.Get("Server"),
		Confidence: Confirmed,
		Evidence:   "answered GET / with " + strconv.Quote(status),
	}
	r.setDetail("status", rest)
	if loc := header.Get("Location"); loc != "" {
		r.setDetail("location", loc)
	}
	if pb := header.Get("X-Powered-By"); pb != "" {
		r.setDetail("powered_by", pb)
	}
	return r, nil
}
