package detect

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/modermatt44/portal/internal/target"
)

func init() { Register(ftpProber{}) }

// ftpProducts are FTP servers recognized in greetings.
var ftpProducts = []string{
	"vsFTPd", "ProFTPD", "Pure-FTPd", "FileZilla Server", "Microsoft FTP Service",
	"Serv-U", "WS_FTP", "wu-ftpd", "CrushFTP", "pyftpdlib", "glFTPd", "bftpd",
}

// ftpProber recognizes FTP servers by their "220" greeting and confirms
// them with FEAT or SYST.
type ftpProber struct{}

func (ftpProber) Name() string     { return "ftp" }
func (ftpProber) Service() Service { return FTP }

// MatchBanner accepts a 220 greeting that does not mention SMTP. Greetings
// that mention FTP are Likely; a bare 220 greeting is only Possible.
func (ftpProber) MatchBanner(banner []byte) *Result {
	code, ok := replyCode(firstLine(banner))
	text := string(banner)
	if !ok || code != 220 || containsFold(text, "SMTP") {
		return nil
	}
	r := &Result{Service: FTP, Confidence: Possible, Evidence: "bare 220 greeting, used by SMTP and FTP"}
	r.Product, r.Version = findProduct(text, ftpProducts)
	if containsFold(text, "FTP") || r.Product != "" {
		r.Confidence = Likely
		r.Evidence = "greeting " + quoteBanner([]byte(firstLine(banner)))
	}
	return r
}

// Confirm sends FEAT (RFC 2389), falling back to SYST. Both are allowed
// before login and have reply codes (211, 215) that SMTP does not use.
func (p ftpProber) Confirm(ctx context.Context, conn net.Conn, t target.Target, banner []byte) (*Result, error) {
	r := p.MatchBanner(banner)
	if r == nil {
		r = &Result{Service: FTP}
	}
	lc := newLineConn(conn)
	defer lc.send("QUIT")

	if err := lc.send("FEAT"); err != nil {
		return nil, err
	}
	code, lines, err := lc.readReply()
	if err != nil {
		return nil, err
	}
	if code == 211 {
		r.Confidence = Confirmed
		r.Evidence = "answered FEAT with 211"
		var feats []string
		if len(lines) > 2 {
			lines = lines[1 : len(lines)-1] // drop "Features:" and "End"
		} else {
			lines = nil
		}
		for _, l := range lines {
			f := strings.TrimSpace(l)
			feats = append(feats, f)
			if strings.EqualFold(f, "AUTH TLS") {
				r.setDetail("auth_tls", "offered")
			}
		}
		if len(feats) > 0 {
			r.setDetail("features", strings.Join(feats, ", "))
		}
		return r, nil
	}

	if err := lc.send("SYST"); err != nil {
		return nil, err
	}
	code, lines, err = lc.readReply()
	if err != nil {
		return nil, err
	}
	if code != 215 {
		return nil, errors.New("neither FEAT nor SYST got an FTP reply")
	}
	r.Confidence = Confirmed
	r.Evidence = "answered SYST with 215"
	r.setDetail("system", strings.Join(lines, " "))
	return r, nil
}
