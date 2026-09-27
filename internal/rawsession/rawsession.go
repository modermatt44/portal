// Package rawsession provides an interactive, netcat-style session over a
// plain TCP or TLS connection. It is portal's fallback when no dedicated
// client exists for a service.
package rawsession

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Options configures a raw session.
type Options struct {
	// TLS wraps the connection in TLS. Certificates are not verified: portal
	// reports the verification result during detection instead.
	TLS bool
	// ServerName is sent as SNI when TLS is enabled.
	ServerName string
	// CRLF translates bare line feeds typed by the user into CRLF, as
	// line-based text protocols (SMTP, IMAP, POP3, FTP) require.
	CRLF bool
	// DialTimeout bounds connection setup. Zero means 10 seconds.
	DialTimeout time.Duration

	// Stdin, Stdout and Stderr are the user's terminal streams.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Run connects to addr and relays data between the connection and the
// user's terminal until the remote side closes the connection or ctx is
// canceled. When Stdin reaches EOF, the write side of the connection is
// closed and Run keeps printing what the server sends until it hangs up.
func Run(ctx context.Context, addr string, opts Options) error {
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}
	conn, err := dial(ctx, addr, opts)
	if err != nil {
		return err
	}
	defer conn.Close()

	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	go func() {
		var src io.Reader = opts.Stdin
		if opts.CRLF {
			src = &crlfReader{r: opts.Stdin}
		}
		_, _ = io.Copy(conn, src)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	_, err = io.Copy(opts.Stdout, conn)
	if err != nil && (errors.Is(err, net.ErrClosed) || ctx.Err() != nil) {
		return nil
	}
	return err
}

func dial(ctx context.Context, addr string, opts Options) (net.Conn, error) {
	d := &net.Dialer{Timeout: opts.DialTimeout}
	if !opts.TLS {
		return d.DialContext(ctx, "tcp", addr)
	}
	td := &tls.Dialer{
		NetDialer: d,
		Config: &tls.Config{
			ServerName:         opts.ServerName,
			InsecureSkipVerify: true, // verification status is reported during detection
		},
	}
	conn, err := td.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TLS connection to %s failed: %w", addr, err)
	}
	return conn, nil
}

// crlfReader rewrites "\n" not preceded by "\r" into "\r\n".
type crlfReader struct {
	r       io.Reader
	prevCR  bool
	pending []byte
}

func (c *crlfReader) Read(p []byte) (int, error) {
	if len(c.pending) == 0 {
		buf := make([]byte, len(p))
		n, err := c.r.Read(buf)
		out := make([]byte, 0, n+8)
		for _, b := range buf[:n] {
			if b == '\n' && !c.prevCR {
				out = append(out, '\r')
			}
			out = append(out, b)
			c.prevCR = b == '\r'
		}
		c.pending = out
		if len(out) == 0 {
			return 0, err
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
