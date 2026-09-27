package detect

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/modermatt44/portal/internal/target"
)

func init() { Register(pop3Prober{}) }

// pop3Products are POP3 servers recognized in greetings.
var pop3Products = []string{
	"Dovecot", "Courier", "Cyrus", "Qpopper", "Microsoft Exchange", "hMailServer", "Zimbra",
}

// pop3Prober recognizes POP3 servers by their "+OK" greeting.
type pop3Prober struct{}

func (pop3Prober) Name() string     { return "pop3" }
func (pop3Prober) Service() Service { return POP3 }

// MatchBanner accepts a "+OK" greeting (RFC 1939 section 4). Greetings that
// mention POP are Confirmed.
func (pop3Prober) MatchBanner(banner []byte) *Result {
	line := firstLine(banner)
	if !strings.HasPrefix(line, "+OK") {
		return nil
	}
	r := &Result{Service: POP3, Confidence: Likely, Evidence: "greeting " + quoteBanner([]byte(line))}
	if containsFold(line, "POP") {
		r.Confidence = Confirmed
	}
	r.Product, r.Version = findProduct(line, pop3Products)
	return r
}

// Confirm sends CAPA (RFC 2449). Any "+OK" or "-ERR" status line confirms
// POP3; a capability list also reveals STLS support.
func (p pop3Prober) Confirm(ctx context.Context, conn net.Conn, t target.Target, banner []byte) (*Result, error) {
	r := p.MatchBanner(banner)
	if r == nil {
		r = &Result{Service: POP3}
	}
	lc := newLineConn(conn)
	if err := lc.send("CAPA"); err != nil {
		return nil, err
	}
	defer lc.send("QUIT")
	status, err := lc.readLine()
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasPrefix(status, "-ERR"):
		r.Confidence = Confirmed
		r.Evidence = "answered CAPA with -ERR"
		return r, nil
	case !strings.HasPrefix(status, "+OK"):
		return nil, errors.New("CAPA got no POP3 status line")
	}
	r.Confidence = Confirmed
	r.Evidence = "answered CAPA"
	var caps []string
	for range 50 {
		line, err := lc.readLine()
		if err != nil || line == "." {
			break
		}
		caps = append(caps, line)
		upper := strings.ToUpper(line)
		switch {
		case upper == "STLS":
			r.setDetail("starttls", "offered")
		case strings.HasPrefix(upper, "IMPLEMENTATION ") && r.Product == "":
			r.Product = strings.TrimSpace(line[len("IMPLEMENTATION "):])
		}
	}
	if len(caps) > 0 {
		r.setDetail("capabilities", strings.Join(caps, " "))
	}
	return r, nil
}
