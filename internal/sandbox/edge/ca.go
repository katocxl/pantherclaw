// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"slices"
	"sync"
	"time"
)

// authority is the session CA (ECDSA P-256). Its key lives only in this
// process's memory (HR-213). It is name-constrained to the mapped hosts and
// signs no IP address, so even a leaked certificate it issued names only a
// host the edge serves itself. Its certificates live at most leafLifetime
// (ADR-0022) and are issued again before they expire.
type authority struct {
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
	fingerprint string
	hosts       []string

	// leafKey is every host certificate's key; leaves caches them.
	leafKey *ecdsa.PrivateKey
	mu      sync.Mutex
	leaves  map[string]*tls.Certificate
	now     func() time.Time
}

func newAuthority(hosts []string, validity time.Duration, clock func() time.Time) (*authority, error) {
	now := clock()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "PantherClaw sandbox session CA"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(validity),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         slices.Clone(hosts),
		ExcludedIPRanges:            []*net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("edge: session CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &authority{
		cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		fingerprint: hex.EncodeToString(sum[:]), hosts: hosts, leafKey: leafKey, leaves: map[string]*tls.Certificate{}, now: clock,
	}, nil
}

// leafLifetime bounds a host certificate (ADR-0022); one is issued again
// leafRenew before it expires.
const (
	leafLifetime = time.Hour
	leafRenew    = 5 * time.Minute
)

// leaf returns the certificate for a mapped host, issued again shortly
// before it expires.
func (a *authority) leaf(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if c, ok := a.leaves[host]; ok && now.Before(c.Leaf.NotAfter.Add(-leafRenew)) {
		return c, nil
	}
	if !slices.Contains(a.hosts, host) {
		return nil, fmt.Errorf("edge: %s is not mapped", host)
	}
	notAfter := now.Add(leafLifetime)
	if notAfter.After(a.cert.NotAfter) {
		notAfter = a.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Minute), NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: a.leafKey, Leaf: cert}
	a.leaves[host] = c
	return c, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}
