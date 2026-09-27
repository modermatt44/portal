package detect

import (
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

func TestSSHMatchBanner(t *testing.T) {
	tests := []struct {
		banner      string
		wantProduct string
		wantVersion string
		wantMatch   bool
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", "OpenSSH", "9.6p1", true},
		{"SSH-2.0-dropbear_2022.83\r\n", "dropbear", "2022.83", true},
		{"SSH-2.0-OpenSSH_for_Windows_9.5\r\n", "OpenSSH for Windows", "9.5", true},
		{"SSH-1.99-Cisco-1.25\r\n", "Cisco-1.25", "", true},
		{"SSH-2.0-Go\r\n", "Go", "", true},
		{"Welcome to the server\r\nSSH-2.0-OpenSSH_8.9\r\n", "OpenSSH", "8.9", true},
		{"220 mail.example.com ESMTP\r\n", "", "", false},
		{"SSH-\r\n", "", "", false},
	}
	for _, tt := range tests {
		r := sshProber{}.MatchBanner([]byte(tt.banner))
		if (r != nil) != tt.wantMatch {
			t.Errorf("MatchBanner(%q) matched = %v, want %v", tt.banner, r != nil, tt.wantMatch)
			continue
		}
		if r == nil {
			continue
		}
		if r.Product != tt.wantProduct || r.Version != tt.wantVersion || r.Confidence != Confirmed {
			t.Errorf("MatchBanner(%q) = %q %q (%s), want %q %q (confirmed)", tt.banner, r.Product, r.Version, r.Confidence, tt.wantProduct, tt.wantVersion)
		}
	}
}

func TestDetectSSH(t *testing.T) {
	s := fakeserver.Start(t, fakeserver.Lines("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", nil))
	rep := detectFake(t, s)
	best := wantBest(t, rep, SSH, Confirmed)
	if best.Product != "OpenSSH" || best.Version != "9.6p1" {
		t.Errorf("product/version = %q %q", best.Product, best.Version)
	}
	if best.Details["protocol"] != "2.0" {
		t.Errorf("protocol detail = %q", best.Details["protocol"])
	}
}
