package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/modermatt44/portal/internal/detect"
	"github.com/modermatt44/portal/internal/term"
)

// printReport writes a human-readable detection report to w. client is the
// command portal would run, if any.
func printReport(w io.Writer, s term.Style, rep *detect.Report, client string) {
	var fields [][2]string
	best, ok := rep.Best()
	switch {
	case ok:
		fmt.Fprintf(w, "%s %s on %s %s\n", s.Green("✓"), s.Bold(best.Label()), rep.Target, s.Dim("("+best.Confidence.String()+")"))
		fields = resultFields(best, rep)
	case len(rep.Candidates) > 0:
		fmt.Fprintf(w, "%s Several services could be on %s:\n", s.Yellow("?"), rep.Target)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for i, c := range rep.Candidates {
			fmt.Fprintf(tw, "  %d. %s\t%s\t%s\n", i+1, c.Label(), s.Dim(c.Confidence.String()), s.Dim(c.Evidence))
		}
		tw.Flush()
		fields = tlsFields(rep.TLS)
	default:
		fmt.Fprintf(w, "%s No known service detected on %s\n", s.Yellow("?"), rep.Target)
		if len(rep.Banner) > 0 {
			fields = append(fields, [2]string{"banner", quote(rep.Banner)})
		}
		fields = append(fields, tlsFields(rep.TLS)...)
	}
	if client != "" {
		fields = append(fields, [2]string{"client", s.Cyan(client)})
	}
	printFields(w, s, fields)
}

// resultFields lists the facts about r worth showing, evidence first.
func resultFields(r detect.Result, rep *detect.Report) [][2]string {
	fields := [][2]string{{"evidence", r.Evidence}}
	keys := make([]string, 0, len(r.Details))
	for k := range r.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fields = append(fields, [2]string{k, r.Details[k]})
	}
	tlsInfo := r.TLS
	if tlsInfo == nil {
		tlsInfo = rep.TLS
	}
	return append(fields, tlsFields(tlsInfo)...)
}

// tlsFields describes a TLS session and its certificate.
func tlsFields(t *detect.TLSInfo) [][2]string {
	if t == nil {
		return nil
	}
	session := t.Version + " · " + t.CipherSuite
	if t.ALPN != "" {
		session += " · ALPN " + t.ALPN
	}
	fields := [][2]string{
		{"tls", session},
		{"subject", t.Subject},
		{"issuer", t.Issuer},
	}
	if len(t.DNSNames) > 0 {
		fields = append(fields, [2]string{"names", strings.Join(t.DNSNames, ", ")})
	}
	fields = append(fields, [2]string{"expires", expiry(t.NotAfter, time.Now())})
	trust := "yes"
	if !t.Verified {
		trust = "no: " + t.VerifyError
	}
	return append(fields, [2]string{"trusted", trust})
}

// expiry describes a certificate's end of validity relative to now.
func expiry(notAfter, now time.Time) string {
	date := notAfter.Format("2006-01-02")
	days := int(notAfter.Sub(now).Hours() / 24)
	switch {
	case notAfter.Before(now):
		return fmt.Sprintf("%s (EXPIRED %d days ago)", date, -days)
	case days == 1:
		return date + " (1 day left)"
	default:
		return fmt.Sprintf("%s (%d days left)", date, days)
	}
}

func printFields(w io.Writer, s term.Style, fields [][2]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range fields {
		if f[1] == "" {
			continue
		}
		fmt.Fprintf(tw, "    %s\t%s\n", s.Dim(f[0]), f[1])
	}
	tw.Flush()
}

// quote renders a banner as a single printable line.
func quote(b []byte) string {
	const max = 100
	s := strings.TrimRight(string(b), "\r\n")
	suffix := ""
	if len(s) > max {
		s, suffix = s[:max], "…"
	}
	return fmt.Sprintf("%q%s", s, suffix)
}

// jsonReport is the --json output format.
type jsonReport struct {
	Target     string          `json:"target"`
	Host       string          `json:"host"`
	Port       int             `json:"port"`
	Service    detect.Service  `json:"service"`
	Label      string          `json:"label"`
	Ambiguous  bool            `json:"ambiguous"`
	Banner     string          `json:"banner,omitempty"`
	TLS        *detect.TLSInfo `json:"tls,omitempty"`
	Candidates []detect.Result `json:"candidates"`
	Client     []string        `json:"client,omitempty"`
	ElapsedMS  int64           `json:"elapsed_ms"`
}

// writeJSON writes rep as indented JSON to w. client is the command line
// portal would run, if any.
func writeJSON(w io.Writer, rep *detect.Report, client []string) error {
	out := jsonReport{
		Target:     rep.Target.String(),
		Host:       rep.Target.Host,
		Port:       rep.Target.Port,
		Service:    detect.Unknown,
		Label:      detect.Unknown.DisplayName(),
		TLS:        rep.TLS,
		Banner:     string(rep.Banner),
		Candidates: rep.Candidates,
		Client:     client,
		ElapsedMS:  rep.Elapsed.Milliseconds(),
	}
	if best, ok := rep.Best(); ok {
		out.Service, out.Label = best.Service, best.Label()
	} else {
		out.Ambiguous = len(rep.Candidates) > 0
	}
	if out.Candidates == nil {
		out.Candidates = []detect.Result{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
