// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
)

// TestHR204_TheKindIsBoundIntoTheSeal: a GitHub App credential's info
// names its kind, and a static one's is exactly what it was before kinds
// existed, so credentials sealed before M8 still open.
func TestHR204_TheKindIsBoundIntoTheSeal(t *testing.T) {
	b := domain.Binding{Org: "o", Connection: "c", Version: 1, AllowedHosts: []string{"api.github.com"}, BrokerKey: "k", Header: "Authorization", Scheme: "Bearer"}
	static := b.Info()
	b.Kind = domain.KindStatic
	if !bytes.Equal(b.Info(), static) {
		t.Fatal("an explicit static kind changed the binding")
	}
	b.Kind = domain.KindGitHubApp
	if app := b.Info(); bytes.Equal(app, static) || !bytes.HasSuffix(app, []byte("kind=github_app\n")) {
		t.Fatalf("info %q", app)
	}
}

// TestHR204_GitHubAppContent: the sealed content round-trips; an App key
// shorter than 2048 bits, not RSA, an uppercase account, a bad issuer or
// an unknown field is refused, and Clear wipes the key.
func TestHR204_GitHubAppContent(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	for _, block := range []*pem.Block{
		{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
		{Type: "PRIVATE KEY", Bytes: pkcs8},
	} {
		g := domain.GitHubApp{V: 1, Issuer: "123456", Installation: 7, Account: "acme", PrivateKey: pem.EncodeToMemory(block)}
		plain, err := g.Encode()
		if err != nil {
			t.Fatal(err)
		}
		back, err := domain.DecodeGitHubApp(plain)
		if err != nil {
			t.Fatal(err)
		}
		if k, err := back.Key(); err != nil || !k.Equal(key) || back.Issuer != "123456" || back.Account != "acme" {
			t.Fatalf("%s: %v", block.Type, err)
		}
		back.Clear()
		if bytes.ContainsFunc(back.PrivateKey, func(r rune) bool { return r != 0 }) {
			t.Fatal("Clear left the key")
		}
	}
	good := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	bad := map[string]domain.GitHubApp{
		"not PEM":      {V: 1, Issuer: "1", Installation: 7, Account: "acme", PrivateKey: []byte("ghp_not_a_key")},
		"uppercase":    {V: 1, Issuer: "1", Installation: 7, Account: "Acme", PrivateKey: good},
		"bad issuer":   {V: 1, Issuer: "app", Installation: 7, Account: "acme", PrivateKey: good},
		"installation": {V: 1, Issuer: "1", Account: "acme", PrivateKey: good},
		"version":      {V: 2, Issuer: "1", Installation: 7, Account: "acme", PrivateKey: good},
	}
	// A 1024-bit key cannot even be generated in FIPS 140-only mode (task
	// test:fips); everywhere else the short key must be refused.
	if short, err := rsa.GenerateKey(rand.Reader, 1024); err == nil {
		bad["short key"] = domain.GitHubApp{V: 1, Issuer: "1", Installation: 7, Account: "acme",
			PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(short)})}
	} else if !fips140.Enabled() {
		t.Fatal(err)
	}
	for name, g := range bad {
		if _, err := g.Encode(); !errors.Is(err, domain.ErrGitHubApp) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := domain.DecodeGitHubApp([]byte(`{"v":1,"issuer":"1","installation":7,"account":"acme","private_key":"","extra":1}`)); !errors.Is(err, domain.ErrGitHubApp) {
		t.Fatalf("an unknown field: %v", err)
	}
}
