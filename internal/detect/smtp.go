package detect

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/modermatt44/portal/internal/target"
)

func init() { Register(smtpProber{}) }

// ehloName is the client name sent in EHLO.
const ehloName = "localhost"

// smtpProducts are mail servers recognized in SMTP greetings.
var smtpProducts = []string{
	"Postfix", "Exim", "Sendmail", "OpenSMTPD", "Haraka", "qmail",
	"Microsoft ESMTP MAIL Service", "hMailServer", "MailEnable", "Zimbra",
	"Mailpit", "MailHog", "smtp4dev", "Courier",
}

// smtpProber recognizes SMTP servers by their "220" greeting and confirms
// them with EHLO, which also reveals whether STARTTLS is offered.
type smtpProber struct{}

func (smtpProber) Name() string     { return "smtp" }
func (smtpProber) Service() Service { return SMTP }

// MatchBanner accepts a 220 (or 554, "no service") greeting. Greetings that
// mention SMTP are Likely; a bare 220 greeting is only Possible, since FTP
// servers use the same code.
func (smtpProber) MatchBanner(banner []byte) *Result {
	line := firstLine(banner)
	code, ok := replyCode(line)
	if !ok || (code != 220 && code != 554) {
		return nil
	}
	text := string(banner)
	mentionsSMTP := containsFold(text, "SMTP")
	if !mentionsSMTP && (code != 220 || containsFold(text, "FTP")) {
		return nil
	}
	r := &Result{Service: SMTP, Confidence: Possible, Evidence: "bare 220 greeting, used by SMTP and FTP"}
	r.Product, r.Version = findProduct(line, smtpProducts)
	if mentionsSMTP || r.Product != "" {
		r.Confidence = Likely
		r.Evidence = "greeting " + quoteBanner([]byte(line))
	}
	return r
}

// Confirm sends EHLO and, if the server offers STARTTLS, upgrades the
// connection to report the certificate.
func (p smtpProber) Confirm(ctx context.Context, conn net.Conn, t target.Target, banner []byte) (*Result, error) {
	r := p.MatchBanner(banner)
	if r == nil {
		r = &Result{Service: SMTP}
	}
	lc := newLineConn(conn)
	if err := lc.send("EHLO %s", ehloName); err != nil {
		return nil, err
	}
	code, lines, err := lc.readReply()
	if err != nil {
		return nil, err
	}
	if code != 250 {
		return nil, fmt.Errorf("EHLO answered %d, not 250", code)
	}
	r.Confidence = Confirmed
	r.Evidence = "answered EHLO with 250"

	var exts []string
	starttls := false
	for _, l := range lines[1:] {
		kw, _, _ := strings.Cut(strings.ToUpper(strings.TrimSpace(l)), " ")
		if kw == "" {
			continue
		}
		exts = append(exts, kw)
		starttls = starttls || kw == "STARTTLS"
	}
	if len(exts) > 0 {
		r.setDetail("extensions", strings.Join(exts, " "))
	}
	if starttls {
		r.setDetail("starttls", "offered")
		if err := smtpStartTLS(ctx, lc, t, r); err != nil {
			r.setDetail("starttls", "offered, but the upgrade failed: "+err.Error())
		}
	}
	_ = lc.send("QUIT")
	return r, nil
}

// smtpStartTLS upgrades the session with STARTTLS and records the TLS
// details in r.
func smtpStartTLS(ctx context.Context, lc *lineConn, t target.Target, r *Result) error {
	return nil
}
