package detect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"

	"github.com/modermatt44/portal/internal/target"
)

// outerALPN is offered on the first TLS handshake. A server that picks one
// of these speaks HTTP, even if the HTTP/1.1 probe later fails (e.g. on an
// HTTP/2-only server).
var outerALPN = []string{"h2", "http/1.1"}

// tlsPhase tries a TLS handshake and, if it succeeds, detects the service
// inside the tunnel. It reports false if the port does not speak TLS.
func (d *detector) tlsPhase(ctx context.Context, rep *Report) ([]Result, bool) {
	raw, err := d.dialTCP(ctx)
	if err != nil {
		d.logf("tls: connect: %v", err)
		return nil, false
	}
	tc, info, err := d.handshake(ctx, raw, outerALPN)
	if err != nil {
		raw.Close()
		d.logf("tls: no handshake (%s)", describeErr(err))
		return nil, false
	}
	rep.TLS = info
	d.logf("tls: %s, %s, ALPN %q, subject %q, issuer %q", info.Version, info.CipherSuite, info.ALPN, info.Subject, info.Issuer)

	dialTLS := func(ctx context.Context) (net.Conn, error) {
		raw, err := d.dialTCP(ctx)
		if err != nil {
			return nil, err
		}
		tc, _, err := d.handshake(ctx, raw, nil)
		if err != nil {
			raw.Close()
			return nil, err
		}
		return tc, nil
	}

	// An HTTP ALPN means no banner will come, so skip straight to the
	// active probes. They use fresh tunnels without ALPN, because a
	// connection that negotiated h2 would not answer HTTP/1.1.
	var results []Result
	httpALPN := info.ALPN == "h2" || info.ALPN == "http/1.1"
	if httpALPN {
		tc.Close()
	} else {
		var banner []byte
		results, banner = d.greet(ctx, dialTLS, tc, "tls")
		if len(banner) > 0 {
			rep.Banner = banner
		}
	}
	if len(results) == 0 {
		results = d.activePhase(ctx, dialTLS, "tls")
	}
	if httpALPN {
		results = append(results, Result{
			Service:    HTTPS,
			Confidence: Confirmed,
			Evidence:   "TLS server negotiated ALPN " + info.ALPN,
		})
	}
	for i := range results {
		if results[i].Service == HTTP {
			results[i].Service = HTTPS
		}
		if results[i].TLS == nil {
			results[i].TLS = info
		}
	}
	return results, true
}

// handshake performs a TLS client handshake on conn within TLSTimeout.
func (d *detector) handshake(ctx context.Context, conn net.Conn, alpn []string) (*tls.Conn, *TLSInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, d.opts.TLSTimeout)
	defer cancel()
	tc := tls.Client(conn, clientTLSConfig(d.t, alpn))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	return tc, newTLSInfo(tc.ConnectionState(), d.t), nil
}

// clientTLSConfig returns a permissive client configuration: portal
// reports certificate problems instead of refusing the connection, and
// accepts old protocol versions and cipher suites so it can identify old
// servers.
func clientTLSConfig(t target.Target, alpn []string) *tls.Config {
	var suites []uint16
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		suites = append(suites, s.ID)
	}
	return &tls.Config{
		ServerName:         serverName(t),
		InsecureSkipVerify: true, // verified separately in newTLSInfo
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       suites,
	}
}

// serverName returns the SNI name for t: its host name, or "" for IP
// addresses, which SNI does not allow.
func serverName(t target.Target) string {
	if t.IsIP() {
		return ""
	}
	return t.Host
}

// newTLSInfo summarizes a completed handshake and verifies the server's
// certificate chain and host name against the system roots.
func newTLSInfo(state tls.ConnectionState, t target.Target) *TLSInfo {
	info := &TLSInfo{
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
	}
	if len(state.PeerCertificates) == 0 {
		info.VerifyError = "server sent no certificate"
		return info
	}
	leaf := state.PeerCertificates[0]
	info.Subject = leaf.Subject.String()
	info.Issuer = leaf.Issuer.String()
	info.DNSNames = leaf.DNSNames
	info.NotBefore = leaf.NotBefore
	info.NotAfter = leaf.NotAfter

	if err := verifyChain(state.PeerCertificates, t.Host); err != nil {
		info.VerifyError = err.Error()
	} else {
		info.Verified = true
	}
	return info
}

func verifyChain(chain []*x509.Certificate, host string) error {
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	host, _, _ = strings.Cut(host, "%") // drop an IPv6 zone
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates})
	return err
}
