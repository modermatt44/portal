package rawsession

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// echoServer accepts one connection, sends a greeting, echoes one line back
// and closes.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "hello\r\n")
		line, _ := bufio.NewReader(conn).ReadString('\n')
		io.WriteString(conn, "echo:"+line)
	}()
	return ln.Addr().String()
}

func TestRunRelays(t *testing.T) {
	addr := echoServer(t)
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, addr, Options{
		CRLF:   true,
		Stdin:  strings.NewReader("ping\n"),
		Stdout: &out,
		Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, want := out.String(), "hello\r\necho:ping\r\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRunDialError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	err = Run(context.Background(), addr, Options{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	if err == nil {
		t.Fatal("Run to a closed port succeeded")
	}
}

func TestCRLFReader(t *testing.T) {
	tests := []struct{ in, want string }{
		{"a\nb\n", "a\r\nb\r\n"},
		{"a\r\nb\r\n", "a\r\nb\r\n"},
		{"no newline", "no newline"},
		{"\n\n", "\r\n\r\n"},
	}
	for _, tt := range tests {
		got, err := io.ReadAll(&crlfReader{r: strings.NewReader(tt.in)})
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tt.want {
			t.Errorf("crlf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
