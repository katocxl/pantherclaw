// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// jwksFixture serves the JWKS of a swappable key registry.
type jwksFixture struct {
	mu      sync.Mutex
	reg     *keys.Registry
	fetches int
	status  int
}

func newRegistry(t *testing.T) *keys.Registry {
	t.Helper()
	reg := keys.NewRegistry()
	for _, p := range []keys.Purpose{keys.PurposePermits, keys.PurposeReceipts} {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func (j *jwksFixture) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.fetches++
	if j.status != 0 {
		w.WriteHeader(j.status)
		return
	}
	b, _ := j.reg.JWKS()
	_, _ = w.Write(b)
}

func (j *jwksFixture) sign(t *testing.T, p keys.Purpose, typ string, c permitClaims) string {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	s, err := j.reg.Signer(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	tok, err := s.Sign(typ, b)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func verifierFixture(t *testing.T) (*permitVerifier, *jwksFixture) {
	t.Helper()
	j := &jwksFixture{reg: newRegistry(t)}
	ts := httptest.NewServer(j)
	t.Cleanup(ts.Close)
	return newPermitVerifier(ts.URL, ts.Client(), "gw-test", testOrg), j
}

func validClaims(w permitWant) permitClaims {
	var c permitClaims
	now := time.Now().Unix()
	c.Iss, c.Aud, c.Jti, c.Iat, c.Exp = "pantherclaw", "gw:gw-test", w.PermitID, now, now+5
	c.Pap.V, c.Pap.Org, c.Pap.Txn, c.Pap.Act, c.Pap.Epoch = 1, testOrg, w.Txn, w.Act, w.Epoch
	return c
}

func newWant() permitWant {
	return permitWant{PermitID: ids.NewV7().String(), Txn: ids.NewV7().String(), Act: strings.Repeat("ab", 32), Epoch: 3}
}

func TestHR009_PermitVerification(t *testing.T) {
	pv, j := verifierFixture(t)
	want := newWant()
	if _, err := pv.verify(context.Background(), j.sign(t, keys.PurposePermits, permitType, validClaims(want)), want); err != nil {
		t.Fatalf("valid permit refused: %v", err)
	}
	for name, tc := range map[string]struct {
		purpose keys.Purpose
		typ     string
		tamper  func(*permitClaims)
	}{
		"audience":    {tamper: func(c *permitClaims) { c.Aud = "gw:other" }},
		"permit id":   {tamper: func(c *permitClaims) { c.Jti = ids.NewV7().String() }},
		"transaction": {tamper: func(c *permitClaims) { c.Pap.Txn = ids.NewV7().String() }},
		"action":      {tamper: func(c *permitClaims) { c.Pap.Act = strings.Repeat("0", 64) }},
		"epoch":       {tamper: func(c *permitClaims) { c.Pap.Epoch = 2 }},
		"org":         {tamper: func(c *permitClaims) { c.Pap.Org = ids.New[ids.Org]().String() }},
		"version":     {tamper: func(c *permitClaims) { c.Pap.V = 2 }},
		"expired":     {tamper: func(c *permitClaims) { c.Exp = time.Now().Unix() }},
		"future iat":  {tamper: func(c *permitClaims) { c.Iat = time.Now().Unix() + 60 }},
		"receipt key": {purpose: keys.PurposeReceipts},
		"typ":         {typ: "pap-receipt+jwt"},
	} {
		c := validClaims(want)
		if tc.tamper != nil {
			tc.tamper(&c)
		}
		p, typ := keys.PurposePermits, permitType
		if tc.purpose != "" {
			p = tc.purpose
		}
		if tc.typ != "" {
			typ = tc.typ
		}
		if _, err := pv.verify(context.Background(), j.sign(t, p, typ, c), want); !errors.Is(err, ErrPermitInvalid) {
			t.Errorf("%s: %v, want ErrPermitInvalid", name, err)
		}
	}
	for _, garbage := range []string{"", "a.b.c", "not a token"} {
		if _, err := pv.verify(context.Background(), garbage, want); !errors.Is(err, ErrPermitInvalid) {
			t.Errorf("token %q: %v", garbage, err)
		}
	}
}

func TestPermitKeyRotationRefetchesJWKS(t *testing.T) {
	pv, j := verifierFixture(t)
	want := newWant()
	if _, err := pv.verify(context.Background(), j.sign(t, keys.PurposePermits, permitType, validClaims(want)), want); err != nil {
		t.Fatal(err)
	}
	rotated := newRegistry(t)
	j.mu.Lock()
	j.reg = rotated
	j.mu.Unlock()
	tok := j.sign(t, keys.PurposePermits, permitType, validClaims(want))
	// Within the refresh interval an unknown kid does not refetch.
	if _, err := pv.verify(context.Background(), tok, want); err == nil {
		t.Fatal("new key accepted without a JWKS refetch")
	}
	pv.mu.Lock()
	pv.fetched = time.Now().Add(-2 * jwksRefreshEvery)
	pv.mu.Unlock()
	if _, err := pv.verify(context.Background(), tok, want); err != nil {
		t.Fatalf("rotated key refused after refetch: %v", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.fetches != 2 {
		t.Fatalf("JWKS fetched %d times, want 2", j.fetches)
	}
}

func TestJWKSUnavailableFailsClosed(t *testing.T) {
	pv, j := verifierFixture(t)
	j.mu.Lock()
	j.status = http.StatusInternalServerError
	j.mu.Unlock()
	want := newWant()
	if _, err := pv.verify(context.Background(), j.sign(t, keys.PurposePermits, permitType, validClaims(want)), want); err == nil {
		t.Fatal("permit accepted without a JWKS")
	}
}
