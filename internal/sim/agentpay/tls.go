// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agentpay

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

// The simulator serves https on loopback (G0 M39 D1124c: a merchant
// endpoint must be an https URL on a sandbox host) with a fixed development
// certificate: an Ed25519 key from a fixed seed, self-signed for localhost,
// 127.0.0.1 and ::1, the same bytes on every run. Only a development server
// or gateway that asks for DevRoots trusts it. DEVELOPMENT ONLY.

var devTLS = sync.OnceValues(func() (tls.Certificate, error) {
	k := devKey("tls")
	t := &x509.Certificate{
		SerialNumber:          big.NewInt(39),
		Subject:               pkix.Name{CommonName: "pantherclaw-sim agentpay (DEVELOPMENT ONLY)"},
		NotBefore:             time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 11, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, t, t, k.Public(), k)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}, nil
})

// DevCertificate is the simulator's fixed development certificate.
func DevCertificate() (tls.Certificate, error) { return devTLS() }

// DevRoots is a pool holding only the simulator's development certificate,
// for a development server's anchor key fetches and a development
// gateway's merchant calls. Never set it in production.
func DevRoots() (*x509.CertPool, error) {
	c, err := devTLS()
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	p.AddCert(c.Leaf)
	return p, nil
}
