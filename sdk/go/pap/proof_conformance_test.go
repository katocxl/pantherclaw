// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/internal/vectors"
	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

type vectorKey struct {
	Seed string `json:"seed"`
	JKT  string `json:"jkt"`
}

func (k vectorKey) private(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(k.Seed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestConformanceWorkloadTokens(t *testing.T) {
	var f struct {
		WorkloadKey vectorKey `json:"workload_key"`
		Cases       []struct {
			Name    string `json:"name"`
			Token   string `json:"token"`
			ATH     string `json:"ath"`
			ValidAt int64  `json:"valid_at"`
			Reject  string `json:"reject"`
		} `json:"cases"`
	}
	vectors.Load(t, "workload_tokens.json", &f)
	pub, _ := f.WorkloadKey.private(t).Public().(ed25519.PublicKey)
	for _, c := range f.Cases {
		claims, err := pap.ParseTokenClaims(c.Token)
		switch {
		case c.Reject != "":
			if err == nil {
				t.Errorf("%s: read, want a refusal", c.Name)
			}
		case err != nil || claims.Cnf.JKT != pap.Thumbprint(pub) || pap.ATH(c.Token) != c.ATH || !claims.ExpiresAt().After(time.Unix(c.ValidAt, 0)):
			t.Errorf("%s: %+v %v", c.Name, claims, err)
		}
	}
}

func TestConformanceProofs(t *testing.T) {
	var f struct {
		Key    vectorKey `json:"key"`
		Proofs []struct {
			Name   string `json:"name"`
			Method string `json:"method"`
			URL    string `json:"url"`
			Body   string `json:"body"`
			Token  string `json:"token"`
			Nonce  string `json:"nonce"`
			IAT    int64  `json:"iat"`
			JTI    string `json:"jti"`
			Proof  string `json:"proof"`
		} `json:"proofs"`
		Checks []struct {
			Name   string `json:"name"`
			Proof  string `json:"proof"`
			Method string `json:"method"`
			URL    string `json:"url"`
			Body   string `json:"body"`
			Token  string `json:"token"`
			Now    int64  `json:"now"`
			Answer string `json:"answer"`
		} `json:"checks"`
	}
	vectors.Load(t, "proofs.json", &f)
	priv := f.Key.private(t)
	for _, c := range f.Proofs {
		got, err := pap.SignProof(priv, pap.ProofParams{
			Method: c.Method, URL: c.URL, Body: []byte(c.Body), Token: c.Token, Nonce: c.Nonce, IssuedAt: time.Unix(c.IAT, 0), JTI: c.JTI,
		})
		if err != nil || got != c.Proof {
			t.Errorf("%s: %v: got %s, want %s", c.Name, err, got, c.Proof)
		}
	}
	for _, c := range f.Checks {
		err := pap.CheckProof(c.Proof, pap.ProofRequest{Method: c.Method, URL: c.URL, Body: []byte(c.Body), Token: c.Token}, time.Unix(c.Now, 0))
		got := "ok"
		var ce *pap.CodeError
		if errors.As(err, &ce) {
			got = string(ce.Code)
		} else if err != nil {
			got = err.Error()
		}
		if got != c.Answer {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Answer)
		}
	}
}

// TestConformanceHTU: the htu signed for a request URL is the one
// PantherClaw's client signs, and a URL it cannot sign for is refused.
func TestConformanceHTU(t *testing.T) {
	var f struct {
		HTUs []struct {
			URL    string `json:"url"`
			HTU    string `json:"htu"`
			Reject bool   `json:"reject"`
		} `json:"htus"`
	}
	vectors.Load(t, "proofs.json", &f)
	if len(f.HTUs) == 0 {
		t.Fatal("no htu vectors")
	}
	for _, c := range f.HTUs {
		got, err := pap.HTU(c.URL)
		switch {
		case c.Reject && err == nil:
			t.Errorf("%q: signed %q, want a refusal", c.URL, got)
		case !c.Reject && (err != nil || got != c.HTU):
			t.Errorf("%q: %q %v, want %q", c.URL, got, err, c.HTU)
		}
	}
}
