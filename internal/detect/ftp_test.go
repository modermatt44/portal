package detect

import (
	"strings"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

func TestFTPMatchBanner(t *testing.T) {
	tests := []struct {
		banner      string
		want        Confidence // 0 means no match
		wantProduct string
		wantVersion string
	}{
		{"220 (vsFTPd 3.0.5)\r\n", Likely, "vsFTPd", "3.0.5"},
		{"220 ProFTPD Server (Debian) [::ffff:10.0.0.1]\r\n", Likely, "ProFTPD", ""},
		{"220-FileZilla Server 1.8.0\r\n220 Please visit https://filezilla-project.org/\r\n", Likely, "FileZilla Server", "1.8.0"},
		{"220 Microsoft FTP Service\r\n", Likely, "Microsoft FTP Service", ""},
		{"220 Service ready\r\n", Possible, "", ""},
		{"220 mail.example.com ESMTP Postfix\r\n", 0, "", ""},
		{"421 Too many connections\r\n", 0, "", ""},
	}
	for _, tt := range tests {
		r := ftpProber{}.MatchBanner([]byte(tt.banner))
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

// ftpHandler emulates an FTP server. If feat is false it rejects FEAT, as
// some old servers do, and only answers SYST.
func ftpHandler(feat bool) func(string) (string, bool) {
	return func(line string) (string, bool) {
		switch strings.ToUpper(line) {
		case "FEAT":
			if feat {
				return "211-Features:\r\n MDTM\r\n AUTH TLS\r\n UTF8\r\n211 End\r\n", false
			}
			return "500 Unknown command.\r\n", false
		case "SYST":
			return "215 UNIX Type: L8\r\n", false
		case "QUIT":
			return "221 Goodbye.\r\n", true
		default:
			return "530 Please login with USER and PASS.\r\n", false
		}
	}
}

func TestDetectFTP(t *testing.T) {
	t.Parallel()
	s := fakeserver.Start(t, fakeserver.Lines("220 (vsFTPd 3.0.5)\r\n", ftpHandler(true)))
	rep := detectFake(t, s)
	best := wantBest(t, rep, FTP, Confirmed)
	if best.Product != "vsFTPd" || best.Version != "3.0.5" {
		t.Errorf("product/version = %q %q", best.Product, best.Version)
	}
	if best.Details["auth_tls"] != "offered" {
		t.Errorf("auth_tls = %q, want offered", best.Details["auth_tls"])
	}
}

// TestDetectBare220FTP checks that a greeting that could be SMTP or FTP is
// resolved by SYST when FEAT is not supported.
func TestDetectBare220FTP(t *testing.T) {
	t.Parallel()
	s := fakeserver.Start(t, fakeserver.Lines("220 Service ready\r\n", ftpHandler(false)))
	rep := detectFake(t, s)
	best := wantBest(t, rep, FTP, Confirmed)
	if best.Details["system"] != "UNIX Type: L8" {
		t.Errorf("system = %q", best.Details["system"])
	}
	if len(rep.Candidates) != 2 || rep.Candidates[1].Service != SMTP || rep.Candidates[1].Confidence != Possible {
		t.Errorf("want SMTP kept as a possible second candidate, got %+v", rep.Candidates)
	}
}
