package detect

import (
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

func TestPOP3MatchBanner(t *testing.T) {
	tests := []struct {
		banner      string
		want        Confidence // 0 means no match
		wantProduct string
	}{
		{"+OK Dovecot (Ubuntu) ready.\r\n", Likely, "Dovecot"},
		{"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>\r\n", Confirmed, ""},
		{"* OK IMAP4 ready\r\n", 0, ""},
		{"-ERR go away\r\n", 0, ""},
	}
	for _, tt := range tests {
		r := pop3Prober{}.MatchBanner([]byte(tt.banner))
		if tt.want == 0 {
			if r != nil {
				t.Errorf("MatchBanner(%q) = %+v, want no match", tt.banner, r)
			}
			continue
		}
		if r == nil {
			t.Errorf("MatchBanner(%q) = nil, want %s", tt.banner, tt.want)
			continue
		}
		if r.Confidence != tt.want || r.Product != tt.wantProduct {
			t.Errorf("MatchBanner(%q) = %s %q, want %s %q", tt.banner, r.Confidence, r.Product, tt.want, tt.wantProduct)
		}
	}
}

func TestDetectPOP3(t *testing.T) {
	s := fakeserver.Start(t, fakeserver.Lines("+OK ready.\r\n", func(line string) (string, bool) {
		switch strings.ToUpper(line) {
		case "CAPA":
			return "+OK\r\nTOP\r\nUIDL\r\nSTLS\r\nIMPLEMENTATION Dovecot\r\n.\r\n", false
		case "QUIT":
			return "+OK Logging out.\r\n", true
		default:
			return "-ERR Unknown command.\r\n", false
		}
	}))
	rep := detectFake(t, s)
	best := wantBest(t, rep, POP3, Confirmed)
	if best.Product != "Dovecot" || best.Details["starttls"] != "offered" {
		t.Errorf("product = %q, details = %v", best.Product, best.Details)
	}
}
