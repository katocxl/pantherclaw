// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sni

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// backend is one org's gateway: a TLS server whose certificate names its
// own hostname, so a client that completes the handshake talked to it.
func backend(t *testing.T, name string) (addr string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.WriteString(c, name)
			}()
		}
	}()
	return ln.Addr().String(), roots
}

func router(t *testing.T, r *Router) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = r.Serve(ctx, ln) }()
	return ln.Addr().String()
}

func dial(addr, name string, roots *x509.CertPool) (string, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS13})
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	b, err := io.ReadAll(c)
	return string(b), err
}

// TestT216_SNIPassthroughReachesOnlyTheNamedOrg: the router passes TLS
// through unterminated to the org the server name names: each org's
// client completes the handshake with its own gateway's certificate, a
// name of another form or an unknown slug is closed, and no name falls
// back to some other org.
//
// Covers: PN-010.4
func TestT216_SNIPassthroughReachesOnlyTheNamedOrg(t *testing.T) {
	aName, bName := "acme.gw.example.test", "beta.gw.example.test"
	aAddr, aRoots := backend(t, aName)
	bAddr, bRoots := backend(t, bName)
	r := &Router{Domain: "example.test"}
	r.Set(map[string]string{"acme": aAddr, "beta": bAddr, "Bad_Slug": aAddr})
	addr := router(t, r)

	if got, err := dial(addr, aName, aRoots); err != nil || got != aName {
		t.Fatalf("acme: %q %v", got, err)
	}
	if got, err := dial(addr, bName, bRoots); err != nil || got != bName {
		t.Fatalf("beta: %q %v", got, err)
	}
	// acme's client never completes a handshake with beta's gateway.
	if _, err := dial(addr, bName, aRoots); err == nil {
		t.Fatal("a client reached another org's gateway with its own trust")
	}
	for _, name := range []string{"unknown.gw.example.test", "acme.example.test", "x.acme.gw.example.test", "acme.gw.example.test.evil", "bad_slug.gw.example.test"} {
		if _, err := dial(addr, name, aRoots); err == nil {
			t.Errorf("%s was routed", name)
		}
	}
}

// TestT218_PerOrgConnectionCap: an org at its connection cap is refused
// while another org on the same host is still served.
//
// Covers: PN-010.4
func TestT218_PerOrgConnectionCap(t *testing.T) {
	r := &Router{Domain: "example.test", PerOrg: 1}
	r.Set(map[string]string{"acme": "127.0.0.1:1", "beta": "127.0.0.1:1"})
	if _, ok := r.acquire("acme"); !ok {
		t.Fatal("first acme connection refused")
	}
	if _, ok := r.acquire("acme"); ok {
		t.Fatal("acme passed its cap")
	}
	if _, ok := r.acquire("beta"); !ok {
		t.Fatal("beta refused because of acme")
	}
	r.release("acme")
	if _, ok := r.acquire("acme"); !ok {
		t.Fatal("a released slot was not freed")
	}
}

// TestSlugNeedsExactlyOneLabel covers the server-name grammar.
func TestSlugNeedsExactlyOneLabel(t *testing.T) {
	r := &Router{Domain: "Example.Test"}
	for name, want := range map[string]string{
		"acme.gw.example.test": "acme", "ACME.GW.EXAMPLE.TEST.": "acme", "a.b.gw.example.test": "",
		"gw.example.test": "", ".gw.example.test": "", "-a.gw.example.test": "",
	} {
		if got := r.Slug(name); got != want {
			t.Errorf("Slug(%q) = %q, want %q", name, got, want)
		}
	}
	if (&Router{}).Slug("acme.gw.") != "" {
		t.Error("no domain routes something")
	}
}
