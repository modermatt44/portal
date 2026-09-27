package detect

import (
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

func TestIMAPMatchBanner(t *testing.T) {
	tests := []struct {
		banner      string
		want        Confidence // 0 means no match
		wantProduct string
		starttls    bool
	}{
		{"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot (Ubuntu) ready.\r\n", Confirmed, "Dovecot", true},
		{"* OK IMAP4 server ready\r\n", Confirmed, "", false},
		{"* OK ready\r\n", Likely, "", false},
		{"* PREAUTH IMAP4rev1 server logged in as alice\r\n", Confirmed, "", false},
		{"+OK POP3 ready\r\n", 0, "", false},
		{"220 ESMTP\r\n", 0, "", false},
	}
	for _, tt := range tests {
		r := imapProber{}.MatchBanner([]byte(tt.banner))
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
		if r.Confidence != tt.want || r.Product != tt.wantProduct || (r.Details["starttls"] == "offered") != tt.starttls {
			t.Errorf("MatchBanner(%q) = %s %q %v, want %s %q starttls=%v", tt.banner, r.Confidence, r.Product, r.Details, tt.want, tt.wantProduct, tt.starttls)
		}
	}
}

func TestDetectIMAP(t *testing.T) {
	s := fakeserver.Start(t, fakeserver.Lines("* OK ready\r\n", func(line string) (string, bool) {
		tag, cmd, _ := strings.Cut(line, " ")
		switch strings.ToUpper(cmd) {
		case "CAPABILITY":
			return "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n" + tag + " OK CAPABILITY completed\r\n", false
		case "LOGOUT":
			return "* BYE\r\n" + tag + " OK LOGOUT completed\r\n", true
		default:
			return tag + " BAD unknown command\r\n", false
		}
	}))
	rep := detectFake(t, s)
	best := wantBest(t, rep, IMAP, Confirmed)
	if best.Details["starttls"] != "offered" {
		t.Errorf("starttls = %q, want offered", best.Details["starttls"])
	}
}
