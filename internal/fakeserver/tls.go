package fakeserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// CertCommonName is the subject common name of the fake servers'
// self-signed certificate.
const CertCommonName = "portal-test"

var (
	certOnce sync.Once
	cert     tls.Certificate
	certErr  error
)

// TLSConfig returns a server configuration with a self-signed certificate
// for localhost and 127.0.0.1. Handlers use it to emulate STARTTLS.
func TLSConfig(t testing.TB) *tls.Config {
	t.Helper()
	certOnce.Do(func() { cert, certErr = selfSigned() })
	if certErr != nil {
		t.Fatalf("fakeserver: generate certificate: %v", certErr)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// StartTLS is like Start, but every connection speaks TLS from the first
// byte. The handshake happens on the handler's first read or write.
func StartTLS(t testing.TB, handle func(conn net.Conn)) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeserver: listen: %v", err)
	}
	return serve(t, tls.NewListener(ln, TLSConfig(t)), handle)
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: CertCommonName, Organization: []string{"portal tests"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
