package detect

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
	"github.com/modermatt44/portal/internal/target"
)

// httptestTarget converts an httptest server's address into a Target.
func httptestTarget(t *testing.T, srv *httptest.Server) target.Target {
	t.Helper()
	addr := srv.Listener.Addr().(*net.TCPAddr)
	return target.Target{Host: "127.0.0.1", Port: addr.Port}
}

func TestDetectHTTPS(t *testing.T) {
	t.Parallel()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		io.WriteString(w, "hello")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // probes cause handshake errors
	srv.StartTLS()
	defer srv.Close()

	rep := detectTarget(t, httptestTarget(t, srv))
	best := wantBest(t, rep, HTTPS, Confirmed)
	if best.Product != "nginx/1.25.3" {
		t.Errorf("product = %q, want the Server header", best.Product)
	}
	if rep.TLS == nil || best.TLS == nil {
		t.Fatal("TLS info missing")
	}
	if !best.ImplicitTLS() {
		t.Error("HTTPS result should be implicit TLS")
	}
	if rep.TLS.Verified || rep.TLS.VerifyError == "" {
		t.Errorf("self-signed certificate reported as verified: %+v", rep.TLS)
	}
	if rep.TLS.ALPN != "http/1.1" || !strings.HasPrefix(rep.TLS.Version, "TLS 1.") {
		t.Errorf("TLS session = %+v", rep.TLS)
	}
	if rep.TLS.NotAfter.IsZero() || rep.TLS.Issuer == "" {
		t.Errorf("certificate details missing: %+v", rep.TLS)
	}
}

func TestDetectTLSUnknownService(t *testing.T) {
	t.Parallel()
	s := fakeserver.StartTLS(t, fakeserver.Silent())
	rep := detectFake(t, s)
	if rep.TLS == nil {
		t.Fatal("TLS not detected")
	}
	if !strings.Contains(rep.TLS.Subject, fakeserver.CertCommonName) {
		t.Errorf("subject = %q, want CN=%s", rep.TLS.Subject, fakeserver.CertCommonName)
	}
	if len(rep.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none", rep.Candidates)
	}
}

func TestDetectIMAPS(t *testing.T) {
	t.Parallel()
	s := fakeserver.StartTLS(t, fakeserver.Lines("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] Dovecot ready.\r\n", nil))
	rep := detectFake(t, s)
	best := wantBest(t, rep, IMAP, Confirmed)
	if !best.ImplicitTLS() {
		t.Error("IMAP inside TLS should be implicit TLS")
	}
	if !strings.HasPrefix(string(rep.Banner), "* OK") {
		t.Errorf("banner = %q, want the greeting from inside the tunnel", rep.Banner)
	}
}

func TestDetectSMTPStartTLS(t *testing.T) {
	t.Parallel()
	cfg := fakeserver.TLSConfig(t)
	s := fakeserver.Start(t, func(conn net.Conn) {
		io.WriteString(conn, "220 mail.test ESMTP Postfix\r\n")
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				io.WriteString(conn, "250-mail.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
			case cmd == "STARTTLS":
				io.WriteString(conn, "220 2.0.0 Ready to start TLS\r\n")
				tc := tls.Server(conn, cfg)
				if tc.Handshake() != nil {
					return
				}
				conn, r = tc, bufio.NewReader(tc)
			case cmd == "QUIT":
				io.WriteString(conn, "221 Bye\r\n")
				return
			}
		}
	})
	rep := detectFake(t, s)
	best := wantBest(t, rep, SMTP, Confirmed)
	if !best.StartTLS || best.TLS == nil || best.ImplicitTLS() {
		t.Fatalf("want a STARTTLS upgrade with TLS details, got %+v", best)
	}
	if best.Details["starttls"] != "offered" {
		t.Errorf("starttls = %q", best.Details["starttls"])
	}
	if rep.TLS != nil {
		t.Error("report TLS should stay nil: the port is plain text")
	}
}
