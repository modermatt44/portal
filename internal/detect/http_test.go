package detect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
	"github.com/modermatt44/portal/internal/target"
)

// detectTarget runs Detect against t and fails the test on error.
func detectTarget(t *testing.T, tg target.Target) *Report {
	t.Helper()
	rep, err := Detect(context.Background(), tg, testOptions(t))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return rep
}

func TestDetectHTTP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %q", r.Method, r.Host)
		}
		w.Header().Set("Server", "Caddy")
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	rep := detectTarget(t, httptestTarget(t, srv))
	best := wantBest(t, rep, HTTP, Confirmed)
	if best.Product != "Caddy" || best.Details["status"] != "302 Found" || best.Details["location"] != "/login" {
		t.Errorf("result = %+v", best)
	}
	if best.TLS != nil || rep.TLS != nil {
		t.Error("plain HTTP reported with TLS")
	}
}

func TestHTTPProbeRejectsNonHTTP(t *testing.T) {
	// A Redis-like server answers the request line with a RESP error.
	s := fakeserver.Start(t, fakeserver.Lines("", func(line string) (string, bool) {
		return "-ERR unknown command\r\n", true
	}))
	conn := dialFake(t, s)
	r, err := httpProber{}.Probe(context.Background(), conn, s.Target)
	if r != nil {
		t.Errorf("Probe = %+v, want no match (err %v)", r, err)
	}
}

func TestHTTPProbeHostHeader(t *testing.T) {
	var got string
	s := fakeserver.Start(t, fakeserver.Lines("", func(line string) (string, bool) {
		if h, ok := strings.CutPrefix(line, "Host: "); ok {
			got = h
		}
		if line == "" {
			return "HTTP/1.1 204 No Content\r\n\r\n", true
		}
		return "", false
	}))
	conn := dialFake(t, s)
	if _, err := (httpProber{}).Probe(context.Background(), conn, s.Target); err != nil {
		t.Fatal(err)
	}
	if got != s.Target.Addr() {
		t.Errorf("Host header = %q, want %q", got, s.Target.Addr())
	}
}
