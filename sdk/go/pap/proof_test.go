// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap_test

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

// htu keeps scheme, host and path: the query and fragment never enter a
// proof, and user information or another scheme is refused.
func TestHTU(t *testing.T) {
	for in, want := range map[string]string{
		"https://gateway.example.test/sdk/local?debug=1#x": "https://gateway.example.test/sdk/local",
		"http://127.0.0.1:8443/v1/wait/abc":                "http://127.0.0.1:8443/v1/wait/abc",
	} {
		if got, err := pap.HTU(in); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"https://user:pw@gateway.example.test/", "ftp://gateway.example.test/", "/sdk/local", "::"} {
		if _, err := pap.HTU(in); err == nil {
			t.Errorf("%s: accepted", in)
		}
	}
}

// A proof with a fresh random id passes PantherClaw's checks for exactly
// its request, and only once the server's nonce is in it.
func TestSignedProofsCheckOut(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	req := pap.ProofRequest{Method: http.MethodPost, URL: "https://gateway.example.test/sdk/local", Body: []byte(`{"tool":"Read"}`)}
	sign := func(nonce string) string {
		p, err := pap.SignProof(priv, pap.ProofParams{Method: req.Method, URL: req.URL + "?q=1", Body: req.Body, Nonce: nonce, IssuedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := pap.CheckProof(sign("Y29uZm9ybWFuY2Utbm9uY2UtMjAyNi0xMC0xMQ"), req, now); err != nil {
		t.Fatalf("a fresh proof: %v", err)
	}
	var ce *pap.CodeError
	if err := pap.CheckProof(sign(""), req, now); !errors.As(err, &ce) || ce.Code != pap.ErrUseNonce {
		t.Fatalf("no nonce yet: %v", err)
	}
	if _, err := pap.SignProof(priv[:31], pap.ProofParams{Method: "GET", URL: req.URL}); err == nil {
		t.Fatal("a short key signed")
	}
	if _, err := pap.SignProof(priv, pap.ProofParams{URL: req.URL}); err == nil {
		t.Fatal("a proof without a method")
	}
}
