// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package idjag_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/idjag"
	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
)

type idp struct {
	srv  *httptest.Server
	rsa  *rsa.PrivateKey
	ec   *ecdsa.PrivateKey
	hits int
}

func newIdP(t *testing.T) *idp {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{rsa: r, ec: e}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.MarshalWrite(w, map[string]string{"issuer": p.srv.URL, "jwks_uri": p.srv.URL + "/keys"})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		p.hits++
		_ = json.MarshalWrite(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &r.PublicKey, KeyID: "rsa", Algorithm: "RS256", Use: "sig"},
			{Key: &e.PublicKey, KeyID: "ec", Algorithm: "ES256", Use: "sig"},
		}})
	})
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) sign(t *testing.T, kid string, hdr map[jose.HeaderKey]any, claims map[string]any) string {
	t.Helper()
	key, alg := any(p.rsa), jose.RS256
	if kid == "ec" {
		key, alg = p.ec, jose.ES256
	}
	opts := &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{"typ": idjag.Typ}}
	for k, v := range hdr {
		opts.ExtraHeaders[k] = v
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const aud = "https://pc.example.com/orgs/0190d0c4-0000-7000-8000-000000000001"

func setup(t *testing.T) (*idp, *idjag.Verifier, domain.Issuer, time.Time, func(map[string]any) map[string]any) {
	p := newIdP(t)
	v := &idjag.Verifier{Client: p.srv.Client(), CheckURL: func(string) error { return nil }}
	iss := domain.Issuer{URL: p.srv.URL, Audience: aud, AudTenant: "org-1", Algorithms: []string{"RS256", "ES256"}}
	now := time.Unix(1_800_000_000, 0)
	base := func(over map[string]any) map[string]any {
		c := map[string]any{
			"iss": p.srv.URL, "sub": "00u1", "aud": aud, "client_id": "agent-client", "jti": "j1",
			"iat": now.Unix() - 10, "exp": now.Unix() + 240, "resource": "https://gw.example.com/mcp-oauth/github",
			"scope": "tickets.read",
		}
		for k, val := range over {
			if val == nil {
				delete(c, k)
			} else {
				c[k] = val
			}
		}
		return c
	}
	return p, v, iss, now, base
}

// TestHR622_AssertionVerifiesOnlyWhatDraft06Allows: every claim rule of
// draft -06 and HR-145's lifetimes refuses, and a good assertion of each
// algorithm verifies.
//
// Covers: F910
func TestHR622_AssertionVerifiesOnlyWhatDraft06Allows(t *testing.T) {
	p, v, iss, now, base := setup(t)
	ctx := context.Background()
	for _, kid := range []string{"rsa", "ec"} {
		a, err := v.Verify(ctx, p.sign(t, kid, nil, base(nil)), iss, now)
		if err != nil || a.Subject != "00u1" || a.ClientID != "agent-client" || !a.HasScope || len(a.Resources) != 1 {
			t.Fatalf("%s: %+v %v", kid, a, err)
		}
	}
	if a, err := v.Verify(ctx, p.sign(t, "rsa", nil, base(map[string]any{"aud": []string{aud}})), iss, now); err != nil || a.JTI != "j1" {
		t.Fatalf("a one-element aud array: %v", err)
	}
	cases := map[string]string{
		"wrong typ":            p.sign(t, "rsa", map[jose.HeaderKey]any{"typ": "JWT"}, base(nil)),
		"embedded jwk":         p.sign(t, "rsa", map[jose.HeaderKey]any{"jwk": map[string]string{"kty": "oct"}}, base(nil)),
		"wrong audience":       p.sign(t, "rsa", nil, base(map[string]any{"aud": "https://pc.example.com/orgs/other"})),
		"two audiences":        p.sign(t, "rsa", nil, base(map[string]any{"aud": []string{aud, "https://x.example.com"}})),
		"wrong issuer":         p.sign(t, "rsa", nil, base(map[string]any{"iss": "https://evil.example.com"})),
		"no client_id":         p.sign(t, "rsa", nil, base(map[string]any{"client_id": nil})),
		"no jti":               p.sign(t, "rsa", nil, base(map[string]any{"jti": nil})),
		"no sub":               p.sign(t, "rsa", nil, base(map[string]any{"sub": nil})),
		"no iat":               p.sign(t, "rsa", nil, base(map[string]any{"iat": nil})),
		"expired":              p.sign(t, "rsa", nil, base(map[string]any{"iat": now.Unix() - 200, "exp": now.Unix() - 1})),
		"too old":              p.sign(t, "rsa", nil, base(map[string]any{"iat": now.Unix() - 400, "exp": now.Unix() + 10})),
		"lives too long":       p.sign(t, "rsa", nil, base(map[string]any{"exp": now.Unix() + 600})),
		"from the future":      p.sign(t, "rsa", nil, base(map[string]any{"iat": now.Unix() + 120, "exp": now.Unix() + 200})),
		"no resource":          p.sign(t, "rsa", nil, base(map[string]any{"resource": nil})),
		"cnf":                  p.sign(t, "rsa", nil, base(map[string]any{"cnf": map[string]string{"jkt": "x"}})),
		"authorization detail": p.sign(t, "rsa", nil, base(map[string]any{"authorization_details": []map[string]string{{"type": "x"}}})),
		"another aud_tenant":   p.sign(t, "rsa", nil, base(map[string]any{"aud_tenant": "org-2"})),
		"unknown kid":          p.sign(t, "nope", nil, base(nil)),
	}
	for name, raw := range cases {
		if _, err := v.Verify(ctx, raw, iss, now); !errors.Is(err, domain.ErrAssertion) {
			t.Errorf("%s: %v", name, err)
		}
	}
	rsaOnly := iss
	rsaOnly.Algorithms = []string{"RS256"}
	if _, err := v.Verify(ctx, p.sign(t, "ec", nil, base(nil)), rsaOnly, now); !errors.Is(err, domain.ErrAssertion) {
		t.Errorf("an algorithm the entry does not allow: %v", err)
	}
	tenanted := iss
	tenanted.Tenant = "acme"
	if _, err := v.Verify(ctx, p.sign(t, "rsa", nil, base(nil)), tenanted, now); !errors.Is(err, domain.ErrAssertion) {
		t.Errorf("a multi-tenant entry without the tenant: %v", err)
	}
	if _, err := v.Verify(ctx, p.sign(t, "rsa", nil, base(map[string]any{"tenant": "acme"})), tenanted, now); err != nil {
		t.Errorf("the pinned tenant: %v", err)
	}
}

// TestIdJagKeysAreCachedAndRefetchedBounded: keys are read once while
// fresh, and an unknown kid does not read them again on every request.
func TestIdJagKeysAreCachedAndRefetchedBounded(t *testing.T) {
	p, v, iss, now, base := setup(t)
	ctx := context.Background()
	for range 3 {
		if _, err := v.Verify(ctx, p.sign(t, "rsa", nil, base(nil)), iss, now); err != nil {
			t.Fatal(err)
		}
		_, _ = v.Verify(ctx, p.sign(t, "nope", nil, base(nil)), iss, now)
	}
	if p.hits != 1 {
		t.Fatalf("keys read %d times", p.hits)
	}
	if err := v.Check(ctx, iss.URL); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := v.Check(ctx, "https://127.0.0.1:1/none"); err == nil {
		t.Fatal("Check of an unreachable issuer passed")
	}
}
