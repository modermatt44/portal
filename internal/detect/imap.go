package detect

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/modermatt44/portal/internal/target"
)

func init() { Register(imapProber{}) }

// imapProducts are IMAP servers recognized in greetings.
var imapProducts = []string{
	"Dovecot", "Cyrus", "Courier", "Microsoft Exchange", "Zimbra", "hMailServer", "Gimap", "UW IMAP",
}

// imapProber recognizes IMAP servers by their untagged "* OK" greeting.
type imapProber struct{}

func (imapProber) Name() string     { return "imap" }
func (imapProber) Service() Service { return IMAP }

// MatchBanner accepts "* OK", "* PREAUTH" and "* BYE" greetings
// (RFC 9051 section 7.1). Greetings that mention IMAP are Confirmed.
func (imapProber) MatchBanner(banner []byte) *Result {
	line := firstLine(banner)
	upper := strings.ToUpper(line)
	if !strings.HasPrefix(upper, "* OK") && !strings.HasPrefix(upper, "* PREAUTH") && !strings.HasPrefix(upper, "* BYE") {
		return nil
	}
	r := &Result{Service: IMAP, Confidence: Likely, Evidence: "untagged greeting " + quoteBanner([]byte(line))}
	if strings.Contains(upper, "IMAP") {
		r.Confidence = Confirmed
	}
	r.Product, r.Version = findProduct(line, imapProducts)
	if strings.Contains(upper, "STARTTLS") {
		r.setDetail("starttls", "offered")
	}
	return r
}

// Confirm sends CAPABILITY and expects an untagged CAPABILITY response.
func (p imapProber) Confirm(ctx context.Context, conn net.Conn, t target.Target, banner []byte) (*Result, error) {
	r := p.MatchBanner(banner)
	if r == nil {
		r = &Result{Service: IMAP}
	}
	lc := newLineConn(conn)
	if err := lc.send("a1 CAPABILITY"); err != nil {
		return nil, err
	}
	defer lc.send("a2 LOGOUT")
	var caps string
	for range 50 {
		line, err := lc.readLine()
		if err != nil {
			return nil, err
		}
		upper := strings.ToUpper(line)
		if c, ok := strings.CutPrefix(upper, "* CAPABILITY "); ok {
			caps = c
		}
		if strings.HasPrefix(upper, "A1 ") {
			break
		}
	}
	if caps == "" {
		return nil, errors.New("no CAPABILITY response")
	}
	r.Confidence = Confirmed
	r.Evidence = "answered CAPABILITY"
	r.setDetail("capabilities", caps)
	if strings.Contains(" "+caps+" ", " STARTTLS ") {
		r.setDetail("starttls", "offered")
	}
	return r, nil
}
