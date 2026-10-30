// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ca

import (
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR500_AHostCertificateNamesNoOrg: a host certificate binds one host
// and one certificate row with the purpose "hosting", and is never read as
// a gateway identity, so it can never act for an org; a gateway
// certificate is never read as a host identity either.
//
// Covers: PN-010.4
func TestHR500_AHostCertificateNamesNoOrg(t *testing.T) {
	a := newCA(t)
	_, csr := request(t)
	pub, err := ParseRequest(csr)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	hid := HostIdentity{Host: ids.NewV7(), Cert: ids.NewV7()}
	iss, err := a.IssueHost(pub, hid, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := verifyClient(t, a, iss.DER, now)
	if err != nil {
		t.Fatalf("host certificate does not verify: %v", err)
	}
	if d := cert.NotAfter.Sub(cert.NotBefore); d > ClientLifetime+ClientSkew {
		t.Errorf("host certificate lives %v", d)
	}
	got, err := ParseHostIdentity(cert)
	if err != nil || got != hid {
		t.Fatalf("host identity %+v %v, want %+v", got, err, hid)
	}
	if _, err := ParseIdentity(cert); err == nil {
		t.Fatal("a host certificate parses as a gateway identity")
	}
	gw, err := a.IssueClient(pub, identity(), now)
	if err != nil {
		t.Fatal(err)
	}
	gcert, err := x509.ParseCertificate(gw.DER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHostIdentity(gcert); err == nil {
		t.Fatal("a gateway certificate parses as a host identity")
	}
	if _, err := a.IssueHost(pub, HostIdentity{Cert: ids.NewV7()}, now); err == nil {
		t.Error("a host certificate without a host was issued")
	}
}

// TestHR500_HostIdentityNeedsTheCanonicalURI: variants of the host URI
// (another purpose, an org segment, extra parts, case) are refused.
//
// Covers: PN-010.4
func TestHR500_HostIdentityNeedsTheCanonicalURI(t *testing.T) {
	h, c := ids.NewV7(), ids.NewV7()
	good := HostIdentity{Host: h, Cert: c}.URI()
	if _, err := ParseHostIdentity(&x509.Certificate{URIs: []*url.URL{good}}); err != nil {
		t.Fatalf("canonical URI refused: %v", err)
	}
	for _, opaque := range []string{
		"admin/host/" + h.String() + "/cert/" + c.String(),
		"hosting/org/" + h.String() + "/cert/" + c.String(),
		"hosting/host/" + h.String() + "/cert/" + c.String() + "/org/x",
		"HOSTING/host/" + h.String() + "/cert/" + c.String(),
		"hosting/host/" + h.String() + "/cert/",
	} {
		if _, err := ParseHostIdentity(&x509.Certificate{URIs: []*url.URL{{Scheme: "pc", Opaque: opaque}}}); err == nil {
			t.Errorf("%q accepted", opaque)
		}
	}
	if _, err := ParseHostIdentity(&x509.Certificate{URIs: []*url.URL{good, good}}); err == nil {
		t.Error("two URIs accepted")
	}
	if _, err := ParseHostIdentity(&x509.Certificate{URIs: []*url.URL{good}, DNSNames: []string{"x"}}); err == nil {
		t.Error("an extra DNS SAN accepted")
	}
}

// TestHR499_AHostedServerCertificateNamesOneHostname: a hosted gateway's
// agent-facing certificate names exactly one <slug>.gw.<domain>, for
// server authentication only, never a wildcard or another form (D210).
//
// Covers: PN-010.4
func TestHR499_AHostedServerCertificateNamesOneHostname(t *testing.T) {
	a := newCA(t)
	_, csr := request(t)
	pub, err := ParseRequest(csr)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	iss, err := a.IssueHostedServer(pub, "acme.gw.h1.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(iss.DER)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "acme.gw.h1.example.test" || len(cert.URIs)+len(cert.IPAddresses) != 0 {
		t.Fatalf("names %v %v %v", cert.DNSNames, cert.URIs, cert.IPAddresses)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: a.Pool(), CurrentTime: now, DNSName: "acme.gw.h1.example.test"}); err != nil {
		t.Fatalf("does not verify for its name: %v", err)
	}
	if _, err := verifyClient(t, a, iss.DER, now); err == nil {
		t.Fatal("a hosted server certificate verifies as a client")
	}
	if d := cert.NotAfter.Sub(cert.NotBefore); d > ServerLifetime+ClientSkew {
		t.Errorf("lives %v", d)
	}
	for _, bad := range []string{"*.gw.h1.example.test", "acme.example.test", "ACME.gw.x", "a.b.gw.x", "acme.gw.", "-a.gw.x"} {
		if _, err := a.IssueHostedServer(pub, bad, now); err == nil {
			t.Errorf("%q issued", bad)
		}
	}
}
