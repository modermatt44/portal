// Package fakeserver runs scripted TCP servers on 127.0.0.1 so that
// detection can be tested without any external network.
package fakeserver

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modermatt44/portal/internal/target"
)

// connTimeout bounds every fake connection so a stuck test fails instead
// of hanging.
const connTimeout = 10 * time.Second

// Server is a fake server listening on 127.0.0.1.
type Server struct {
	// Target is the address the server listens on.
	Target target.Target

	ln net.Listener
	wg sync.WaitGroup
}

// Start listens on a random port on 127.0.0.1 and calls handle in a new
// goroutine for every connection. The connection is closed when handle
// returns. The server is shut down when the test ends.
func Start(t testing.TB, handle func(conn net.Conn)) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeserver: listen: %v", err)
	}
	return serve(t, ln, handle)
}

func serve(t testing.TB, ln net.Listener, handle func(conn net.Conn)) *Server {
	addr := ln.Addr().(*net.TCPAddr)
	s := &Server{Target: target.Target{Host: "127.0.0.1", Port: addr.Port}, ln: ln}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(connTimeout))
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		s.wg.Wait()
	})
	return s
}

// Silent returns a handler that accepts the connection, sends nothing and
// discards whatever the client sends until it hangs up.
func Silent() func(net.Conn) {
	return func(conn net.Conn) { io.Copy(io.Discard, conn) }
}

// Lines returns a handler for line-based protocols. It sends banner (which
// may be empty), then calls respond for every line the client sends, with
// the line terminator removed. respond returns the text to send back and
// whether to close the connection afterwards. A nil respond ignores input.
func Lines(banner string, respond func(line string) (reply string, hangUp bool)) func(net.Conn) {
	return func(conn net.Conn) {
		if banner != "" {
			if _, err := io.WriteString(conn, banner); err != nil {
				return
			}
		}
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if respond == nil {
				continue
			}
			reply, hangUp := respond(strings.TrimRight(line, "\r\n"))
			if reply != "" {
				if _, err := io.WriteString(conn, reply); err != nil {
					return
				}
			}
			if hangUp {
				return
			}
		}
	}
}
