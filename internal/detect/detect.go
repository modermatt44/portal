// Package detect identifies the service listening on a TCP port.
//
// Detection runs in phases, each bounded by its own timeout:
//
//  1. Banner: connect and wait briefly for the server to speak first, then
//     match the greeting against every BannerProber.
//  2. TLS: if the server stays silent, try a TLS handshake. If it succeeds,
//     run the banner and active phases again inside the tunnel.
//  3. Active: run every ActiveProber concurrently, each on a fresh
//     connection.
//  4. Port hint: if nothing matched, report the service conventionally
//     found on the port, marked as unverified.
//
// Protocols are added by implementing Prober plus BannerProber or
// ActiveProber in a new file and calling Register from its init function.
package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Service identifies an application protocol.
type Service string

// Services portal can detect.
const (
	SSH        Service = "ssh"
	HTTP       Service = "http"
	HTTPS      Service = "https"
	PostgreSQL Service = "postgresql"
	MySQL      Service = "mysql"
	Redis      Service = "redis"
	SMTP       Service = "smtp"
	FTP        Service = "ftp"
	IMAP       Service = "imap"
	POP3       Service = "pop3"
	MongoDB    Service = "mongodb"

	// Unknown means no protocol was identified. It is never a candidate in
	// a Report; callers use it for the raw-session fallback.
	Unknown Service = "unknown"
)

var displayNames = map[Service]string{
	SSH:        "SSH",
	HTTP:       "HTTP",
	HTTPS:      "HTTPS",
	PostgreSQL: "PostgreSQL",
	MySQL:      "MySQL",
	Redis:      "Redis",
	SMTP:       "SMTP",
	FTP:        "FTP",
	IMAP:       "IMAP",
	POP3:       "POP3",
	MongoDB:    "MongoDB",
	Unknown:    "unknown service",
}

// DisplayName returns a human-readable name such as "PostgreSQL".
func (s Service) DisplayName() string {
	if n, ok := displayNames[s]; ok {
		return n
	}
	return string(s)
}

// Known reports whether s is one of the services portal can detect.
func (s Service) Known() bool {
	_, ok := displayNames[s]
	return ok && s != Unknown
}

// Services returns every detectable service, sorted by name.
func Services() []Service {
	var out []Service
	for s := range displayNames {
		if s != Unknown {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Confidence says how strongly the evidence supports a Result.
type Confidence int

// Confidence levels, from weakest to strongest.
const (
	// PortHint means only the port number suggests the service.
	PortHint Confidence = iota + 1
	// Possible means the evidence fits this and other protocols equally,
	// e.g. a bare "220" greeting shared by SMTP and FTP.
	Possible
	// Likely means a signature matched but the protocol was not exercised.
	Likely
	// Confirmed means the server answered a protocol exchange correctly.
	Confirmed
)

var confidenceNames = map[Confidence]string{
	PortHint:  "port-hint",
	Possible:  "possible",
	Likely:    "likely",
	Confirmed: "confirmed",
}

// String returns the lower-case name of c, e.g. "confirmed".
func (c Confidence) String() string {
	if n, ok := confidenceNames[c]; ok {
		return n
	}
	return fmt.Sprintf("Confidence(%d)", int(c))
}

// MarshalText implements encoding.TextMarshaler so that JSON output uses
// the name instead of the number.
func (c Confidence) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// Result is one candidate identification of the service on a port.
type Result struct {
	// Service is the identified protocol.
	Service Service `json:"service"`
	// Product is the server software, e.g. "OpenSSH" or "nginx", if known.
	Product string `json:"product,omitempty"`
	// Version is the server software version, if known.
	Version string `json:"version,omitempty"`
	// Confidence says how strong the evidence is.
	Confidence Confidence `json:"confidence"`
	// Evidence briefly describes what was observed.
	Evidence string `json:"evidence,omitempty"`
	// Details holds protocol-specific facts such as "starttls": "offered".
	Details map[string]string `json:"details,omitempty"`
	// TLS describes the TLS session the service was found in, if any.
	TLS *TLSInfo `json:"tls,omitempty"`
	// StartTLS reports that TLS describes a STARTTLS upgrade rather than a
	// connection that is encrypted from the first byte.
	StartTLS bool `json:"starttls,omitempty"`
}

// Label returns a short description such as "PostgreSQL",
// "MySQL 8.0.36" or "SSH (OpenSSH 9.6p1)".
func (r Result) Label() string {
	name := r.Service.DisplayName()
	switch {
	case r.Product != "" && r.Product != name:
		if r.Version != "" {
			return fmt.Sprintf("%s (%s %s)", name, r.Product, r.Version)
		}
		return fmt.Sprintf("%s (%s)", name, r.Product)
	case r.Version != "":
		return name + " " + r.Version
	default:
		return name
	}
}

// ImplicitTLS reports whether the service is spoken inside TLS from the
// first byte, as opposed to plain text or a STARTTLS upgrade.
func (r Result) ImplicitTLS() bool { return r.TLS != nil && !r.StartTLS }

func (r *Result) setDetail(key, value string) {
	if r.Details == nil {
		r.Details = make(map[string]string)
	}
	r.Details[key] = value
}

// TLSInfo describes a TLS session and the server's certificate.
type TLSInfo struct {
	// Version is the negotiated protocol version, e.g. "TLS 1.3".
	Version string `json:"version"`
	// CipherSuite is the negotiated cipher suite.
	CipherSuite string `json:"cipher_suite"`
	// ALPN is the negotiated application protocol, e.g. "h2", if any.
	ALPN string `json:"alpn,omitempty"`
	// Subject is the leaf certificate's subject.
	Subject string `json:"subject"`
	// Issuer is the leaf certificate's issuer.
	Issuer string `json:"issuer"`
	// DNSNames are the names the certificate is valid for.
	DNSNames []string `json:"dns_names,omitempty"`
	// NotBefore and NotAfter bound the certificate's validity.
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// Verified reports whether the certificate chains to a trusted root and
	// matches the host name.
	Verified bool `json:"verified"`
	// VerifyError explains why verification failed.
	VerifyError string `json:"verify_error,omitempty"`
}

// serviceAliases are alternative names accepted by ParseService.
var serviceAliases = map[string]Service{
	"postgres": PostgreSQL,
	"pg":       PostgreSQL,
	"mariadb":  MySQL,
	"mongo":    MongoDB,
}

// ParseService returns the service with the given name or common alias
// (e.g. "postgres", "mariadb", "mongo"), ignoring case.
func ParseService(name string) (Service, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if s, ok := serviceAliases[name]; ok {
		return s, true
	}
	s := Service(name)
	return s, s.Known()
}
