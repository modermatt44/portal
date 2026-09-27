package detect

import (
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

func TestSMTPMatchBanner(t *testing.T) {
	tests := []struct {
		banner      string
		want        Confidence // 0 means no match
		wantProduct string
		wantVersion string
	}{
		{"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", Likely, "Postfix", ""},
		{"220 mx.example.org ESMTP Exim 4.96 Mon, 01 Jan 2024 10:00:00 +0000\r\n", Likely, "Exim", "4.96"},
		{"220-mail.example.com ESMTP Sendmail 8.15.2/8.15.2; ready\r\n220 ok\r\n", Likely, "Sendmail", "8.15.2"},
		{"554 5.7.1 No SMTP service here\r\n", Likely, "", ""},
		{"220 Service ready\r\n", Possible, "", ""},
		{"220 (vsFTPd 3.0.5)\r\n", 0, "", ""},
		{"SSH-2.0-OpenSSH_9.6\r\n", 0, "", ""},
		{"+OK POP3 ready\r\n", 0, "", ""},
	}
	for _, tt := range tests {
		r := smtpProber{}.MatchBanner([]byte(tt.banner))
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
		if r.Confidence != tt.want || r.Product != tt.wantProduct || r.Version != tt.wantVersion {
			t.Errorf("MatchBanner(%q) = %s %q %q, want %s %q %q", tt.banner, r.Confidence, r.Product, r.Version, tt.want, tt.wantProduct, tt.wantVersion)
		}
	}
}

// smtpHandler emulates a mail server; ehlo is the EHLO reply.
func smtpHandler(banner, ehlo string) func(string) (string, bool) {
	return func(line string) (string, bool) {
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			return ehlo, false
		case cmd == "QUIT":
			return "221 2.0.0 Bye\r\n", true
		default:
			return "502 5.5.2 Error: command not recognized\r\n", false
		}
	}
}

func TestDetectSMTP(t *testing.T) {
	banner := "220 mail.test ESMTP Postfix\r\n"
	s := fakeserver.Start(t, fakeserver.Lines(banner, smtpHandler(banner,
		"250-mail.test\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 8BITMIME\r\n")))
	rep := detectFake(t, s)
	best := wantBest(t, rep, SMTP, Confirmed)
	if best.Product != "Postfix" {
		t.Errorf("product = %q, want Postfix", best.Product)
	}
	if got := best.Details["extensions"]; got != "PIPELINING SIZE 8BITMIME" {
		t.Errorf("extensions = %q", got)
	}
	if _, ok := best.Details["starttls"]; ok {
		t.Error("starttls reported but not offered")
	}
}

// TestDetectBare220SMTP checks that a greeting that could be SMTP or FTP is
// resolved by EHLO.
func TestDetectBare220SMTP(t *testing.T) {
	banner := "220 Service ready\r\n"
	s := fakeserver.Start(t, fakeserver.Lines(banner, smtpHandler(banner, "250 hello\r\n")))
	rep := detectFake(t, s)
	wantBest(t, rep, SMTP, Confirmed)
}
