// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestHR502_TheHostedTLSKeyStaysInTheVolume: the agent-facing key is made
// once in the gateway's volume and only its public half leaves, in a
// certificate request; the same key is kept across renewals, which come at
// two thirds of the certificate's lifetime (D210).
//
// Covers: PN-010.4
func TestHR502_TheHostedTLSKeyStaysInTheVolume(t *testing.T) {
	dir := t.TempDir()
	keyFile, certFile := filepath.Join(dir, "tls", "key.pem"), filepath.Join(dir, "tls", "cert.pem")
	key, err := loadOrMakeKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadOrMakeKey(keyFile)
	if err != nil || !again.Equal(key) {
		t.Fatal("the key changed on reload")
	}
	now := time.Now()
	var sent [][]byte
	h := &hostedTLS{keyFile: keyFile, certFile: certFile, key: key, log: slog.New(slog.DiscardHandler), now: func() time.Time { return now }}
	h.issue = func(_ context.Context, csr []byte) ([]byte, error) {
		sent = append(sent, csr)
		req, err := x509.ParseCertificateRequest(csr)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(len(sent))), Subject: pkix.Name{CommonName: "acme.gw.h1.example.test"},
			DNSNames: []string{"acme.gw.h1.example.test"}, NotBefore: now, NotAfter: now.Add(7 * 24 * time.Hour),
		}
		_, caKey, _ := ed25519.GenerateKey(rand.Reader)
		return x509.CreateCertificate(rand.Reader, tmpl, tmpl, req.PublicKey, caKey)
	}
	if err := h.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(keyFile)
	seed := key.Seed()
	for _, csr := range sent {
		if bytes.Contains(csr, seed) || bytes.Contains(csr, raw) {
			t.Fatal("the private key left in a request")
		}
	}
	c := h.cur.Load()
	if h.due(c) {
		t.Fatal("a fresh certificate is due")
	}
	if at := renewAt(c.Leaf); at.Sub(c.Leaf.NotBefore) != c.Leaf.NotAfter.Sub(c.Leaf.NotBefore)*2/3 {
		t.Fatalf("renews at %v", at)
	}
	now = renewAt(c.Leaf)
	if !h.due(c) {
		t.Fatal("not due at two thirds")
	}
	loaded, err := h.loadCert()
	if err != nil || !bytes.Equal(loaded.Certificate[0], c.Certificate[0]) {
		t.Fatalf("certificate on disk: %v", err)
	}
	if fi, err := os.Stat(keyFile); err != nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("key file mode %v %v", fi.Mode(), err)
	}
}
