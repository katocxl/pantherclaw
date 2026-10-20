// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2a_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
)

// TestHR322_CardPinAndDrift: a card pins when its signature verifies with
// the pinned key and it declares the interface and skills; a later read of
// a changed card, or of one whose signature was stripped, is drift.
func TestHR322_CardPinAndDrift(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sim := a2asim.New(a2asim.Options{SigningKey: key, KeyID: "k1"}, a2asim.Faults{}, nil)
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	jwks, err := wire.PublicJWKS(map[string]crypto.PublicKey{"k1": key.Public()})
	if err != nil {
		t.Fatal(err)
	}
	req := wire.PinRequest{
		CardURL: ts.URL + wire.CardPath, Binding: wire.BindingHTTPJSON, URL: ts.URL + a2asim.RESTPath, Keys: jwks, Skills: []string{"refunds"},
	}
	pinned, err := wire.Pin(t.Context(), ts.Client(), req)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	if _, err := wire.Recheck(t.Context(), ts.Client(), req.CardURL, pinned.Digest[:], jwks); err != nil {
		t.Fatalf("recheck unchanged card: %v", err)
	}
	sim.SetFaults(a2asim.Faults{Description: "now also moves money"})
	if _, err := wire.Recheck(t.Context(), ts.Client(), req.CardURL, pinned.Digest[:], jwks); !errors.Is(err, wire.ErrDrift) {
		t.Fatalf("recheck drifted card: %v, want ErrDrift", err)
	}
	// Another key pinned: the card does not pin.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherJWKS, _ := wire.PublicJWKS(map[string]crypto.PublicKey{"k1": other.Public()})
	req.Keys = otherJWKS
	if _, err := wire.Pin(t.Context(), ts.Client(), req); !errors.Is(err, wire.ErrCardSignature) {
		t.Fatalf("pin with another key: %v", err)
	}
	// An interface or skill the card does not declare.
	req.Keys, req.Skills = jwks, []string{"transfers"}
	if _, err := wire.Pin(t.Context(), ts.Client(), req); !errors.Is(err, wire.ErrSkill) {
		t.Fatalf("pin undeclared skill: %v", err)
	}
	req.Skills, req.URL = nil, "https://evil.example/a2a"
	if _, err := wire.Pin(t.Context(), ts.Client(), req); !errors.Is(err, wire.ErrInterface) {
		t.Fatalf("pin undeclared interface: %v", err)
	}
}

func TestFetchCardRefusesRedirectsAndOtherAnswers(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/card", http.StatusFound)
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`{"name":"x"}`))
		case "/big":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(make([]byte, wire.MaxCardBytes+1))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	for _, p := range []string{"/redirect", "/html", "/big", "/missing"} {
		if _, err := wire.FetchCard(t.Context(), ts.Client(), ts.URL+p); !errors.Is(err, wire.ErrFetch) {
			t.Errorf("%s: %v, want ErrFetch", p, err)
		}
	}
}
