package detect

import (
	"strings"
	"unicode"
)

func init() { Register(sshProber{}) }

// sshProber recognizes SSH servers by their identification string.
type sshProber struct{}

func (sshProber) Name() string     { return "ssh" }
func (sshProber) Service() Service { return SSH }

// MatchBanner looks for the identification string
// "SSH-protoversion-softwareversion comments" (RFC 4253 section 4.2).
// Servers may send other lines before it.
func (sshProber) MatchBanner(banner []byte) *Result {
	for _, line := range bannerLines(banner) {
		rest, ok := strings.CutPrefix(line, "SSH-")
		if !ok {
			continue
		}
		proto, software, ok := strings.Cut(rest, "-")
		if !ok || proto == "" {
			continue
		}
		software, comment, _ := strings.Cut(software, " ")
		product, version := splitSSHSoftware(software)
		r := &Result{
			Service:    SSH,
			Product:    product,
			Version:    version,
			Confidence: Confirmed,
			Evidence:   "identification string " + quoteBanner([]byte(line)),
		}
		r.setDetail("protocol", proto)
		if comment != "" {
			r.setDetail("comment", comment)
		}
		return r
	}
	return nil
}

// splitSSHSoftware splits "OpenSSH_9.6p1" into "OpenSSH" and "9.6p1", and
// "OpenSSH_for_Windows_9.5" into "OpenSSH for Windows" and "9.5".
func splitSSHSoftware(s string) (product, version string) {
	i := strings.LastIndex(s, "_")
	if i <= 0 || i == len(s)-1 || !unicode.IsDigit(rune(s[i+1])) {
		return strings.ReplaceAll(s, "_", " "), ""
	}
	return strings.ReplaceAll(s[:i], "_", " "), s[i+1:]
}
