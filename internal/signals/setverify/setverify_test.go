// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package setverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	issuer   = "https://idp.example.com"
	audience = "https://pc.example.com/v1/ssf/org/tx"
	caepType = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

type staticKeys map[string]any

func (k staticKeys) Key(_ context.Context, kid string) (any, error) {
	if v, ok := k[kid]; ok {
		return v, nil
	}
	return nil, errUnknownKid
}

type fixture struct {
	rsa   *rsa.PrivateKey
	ec    *ecdsa.PrivateKey
	other *rsa.PrivateKey
	keys  staticKeys
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	o, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{rsa: r, ec: e, other: o, keys: staticKeys{"r1": &r.PublicKey, "e1": &e.PublicKey}}
}

func claimsJSON(mut func(map[string]any)) []byte {
	c := map[string]any{
		"iss": issuer, "aud": audience, "iat": now.Unix(), "jti": "jti-1",
		"sub_id": map[string]any{"format": "iss_sub", "iss": "https://login.example.com", "sub": "user-7"},
		"events": map[string]any{caepType: map[string]any{"event_timestamp": now.Unix()}},
	}
	if mut != nil {
		mut(c)
	}
	b, _ := json.Marshal(c)
	return b
}

func sign(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, extra map[jose.HeaderKey]any, payload []byte) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("secevent+jwt")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	for k, v := range extra {
		opts = opts.WithHeader(k, v)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// rawToken assembles a token from a header and payload with a given
// signature (for algorithms go-jose refuses to produce, like none).
func rawToken(header map[string]any, payload []byte, sig string) string {
	h, _ := json.Marshal(header)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + sig
}

func (f fixture) tx() Transmitter {
	return Transmitter{Issuer: issuer, Audience: audience, Keys: f.keys}
}

func TestVerifyAccepts(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		alg jose.SignatureAlgorithm
		key any
		kid string
	}{{jose.RS256, f.rsa, "r1"}, {jose.ES256, f.ec, "e1"}} {
		set, err := Verify(context.Background(), f.tx(), sign(t, c.alg, c.key, c.kid, nil, claimsJSON(nil)), now)
		if err != nil {
			t.Fatalf("%s: %v", c.alg, err)
		}
		if set.JTI != "jti-1" || set.EventType != caepType || set.Subject.Format != "iss_sub" || set.Subject.Sub != "user-7" ||
			!set.IssuedAt.Equal(now) {
			t.Errorf("%s: set = %+v", c.alg, set)
		}
	}
	// aud as an array, subject inside the event (pre-sub_id CAEP).
	payload := claimsJSON(func(c map[string]any) {
		c["aud"] = []string{"other", audience}
		delete(c, "sub_id")
		c["events"] = map[string]any{caepType: map[string]any{"subject": map[string]any{"format": "email", "email": "a@example.com"}}}
	})
	set, err := Verify(context.Background(), f.tx(), sign(t, jose.RS256, f.rsa, "r1", nil, payload), now)
	if err != nil || set.Subject.Format != "email" || set.Subject.Email != "a@example.com" {
		t.Fatalf("set = %+v, err = %v", set, err)
	}
}

// TestT113_ForgedOrMalformedSETsAreRefused: a SET is accepted only when
// its signature verifies with the transmitter's pinned key under RS256 or
// ES256, no key comes from its header, and iss, aud, iat, jti and events
// hold (HR-261).
func TestT113_ForgedOrMalformedSETsAreRefused(t *testing.T) {
	f := newFixture(t)
	good := claimsJSON(nil)
	jwk := jose.JSONWebKey{Key: &f.other.PublicKey, KeyID: "r1", Algorithm: "RS256", Use: "sig"}
	cases := []struct {
		name  string
		token func() string
		code  string
	}{
		{"forged signature (another key, same kid)", func() string { return sign(t, jose.RS256, f.other, "r1", nil, good) }, CodeAuthFailed},
		{"tampered payload", func() string {
			tok := sign(t, jose.RS256, f.rsa, "r1", nil, good)
			parts := strings.Split(tok, ".")
			parts[1] = base64.RawURLEncoding.EncodeToString(claimsJSON(func(c map[string]any) { c["jti"] = "other" }))
			return strings.Join(parts, ".")
		}, CodeAuthFailed},
		{"alg none", func() string { return rawToken(map[string]any{"alg": "none", "kid": "r1"}, good, "") }, CodeAuthFailed},
		{"alg HS256 with the public key as secret", func() string {
			return sign(t, jose.HS256, []byte(strings.Repeat("k", 32)), "r1", nil, good)
		}, CodeAuthFailed},
		{"alg PS256", func() string { return sign(t, jose.PS256, f.rsa, "r1", nil, good) }, CodeAuthFailed},
		{"ES256 header on an RSA key", func() string { return sign(t, jose.ES256, f.ec, "r1", nil, good) }, CodeAuthFailed},
		{"RS256 header on an EC key", func() string { return sign(t, jose.RS256, f.rsa, "e1", nil, good) }, CodeAuthFailed},
		{"header jwk", func() string {
			return sign(t, jose.RS256, f.other, "r1", map[jose.HeaderKey]any{"jwk": jwk}, good)
		}, CodeAuthFailed},
		{"header jku", func() string {
			return sign(t, jose.RS256, f.other, "r1", map[jose.HeaderKey]any{"jku": "https://evil.example/jwks"}, good)
		}, CodeAuthFailed},
		{"header x5u", func() string {
			return sign(t, jose.RS256, f.other, "r1", map[jose.HeaderKey]any{"x5u": "https://evil.example/cert"}, good)
		}, CodeAuthFailed},
		{"header crit", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", map[jose.HeaderKey]any{"crit": []string{"exp"}}, good)
		}, CodeAuthFailed},
		{"no kid", func() string { return sign(t, jose.RS256, f.rsa, "", nil, good) }, CodeInvalidKey},
		{"unknown kid", func() string { return sign(t, jose.RS256, f.rsa, "zz", nil, good) }, CodeInvalidKey},
		{"wrong iss", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { c["iss"] = "https://idp.example.com/" }))
		}, CodeInvalidIssuer},
		{"no iss", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { delete(c, "iss") }))
		}, CodeInvalidIssuer},
		{"wrong aud", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { c["aud"] = "https://pc.example.com/v1/ssf/org/other" }))
		}, CodeInvalidAudience},
		{"aud array without us", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { c["aud"] = []string{"a", "b"} }))
		}, CodeInvalidAudience},
		{"stale iat", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { c["iat"] = now.Add(-6 * time.Minute).Unix() }))
		}, CodeInvalidRequest},
		{"future iat", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { c["iat"] = now.Add(6 * time.Minute).Unix() }))
		}, CodeInvalidRequest},
		{"no jti", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { delete(c, "jti") }))
		}, CodeInvalidRequest},
		{"two events", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) {
				c["events"] = map[string]any{caepType: map[string]any{}, caepType + "x": map[string]any{}}
			}))
		}, CodeInvalidRequest},
		{"no events", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { delete(c, "events") }))
		}, CodeInvalidRequest},
		{"event not an object", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { c["events"] = map[string]any{caepType: "x"} }))
		}, CodeInvalidRequest},
		{"oversize body", func() string {
			return sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(func(c map[string]any) { c["pad"] = strings.Repeat("a", MaxToken) }))
		}, CodeInvalidRequest},
		{"JSON serialization", func() string { return `{"payload":"e30","signatures":[]}` }, CodeInvalidRequest},
		{"garbage", func() string { return "not a token" }, CodeInvalidRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(context.Background(), f.tx(), c.token(), now)
			if err == nil {
				t.Fatal("accepted")
			}
			if got := CodeOf(err); got != c.code {
				t.Errorf("code = %s, want %s (%v)", got, c.code, err)
			}
		})
	}
}

func TestCheckJWKSURI(t *testing.T) {
	for _, c := range []struct {
		issuer, uri string
		ok          bool
	}{
		{"https://idp.example.com", "https://idp.example.com/keys", true},
		{"https://idp.example.com/tenant", "https://IDP.example.com/.well-known/jwks.json", true},
		{"https://idp.example.com", "https://evil.example.com/keys", false},
		{"https://idp.example.com", "http://idp.example.com/keys", false},
		{"https://idp.example.com", "https://idp.example.com:8443/keys", false},
		{"https://idp.example.com", "https://u:p@idp.example.com/keys", false},
		{"https://idp.example.com", "https://idp.example.com/keys?x=1", false},
		{"http://idp.example.com", "https://idp.example.com/keys", false},
	} {
		if err := CheckJWKSURI(c.issuer, c.uri); (err == nil) != c.ok {
			t.Errorf("CheckJWKSURI(%q, %q) = %v", c.issuer, c.uri, err)
		}
	}
}

func TestJWKSCacheAndLimits(t *testing.T) {
	f := newFixture(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &f.rsa.PublicKey, KeyID: "r1", Algorithm: "RS256", Use: "sig"},
		{Key: &f.ec.PublicKey, KeyID: "e1", Use: "sig"},
		{Key: &small.PublicKey, KeyID: "weak", Algorithm: "RS256"},
		{Key: &f.other.PublicKey, KeyID: "enc", Use: "enc"},
		{Key: f.other, KeyID: "private"},
	}}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	var fetches atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	clock := now
	host := strings.TrimPrefix(srv.URL, "https://")
	j, err := NewJWKS(srv.Client(), "https://"+host, srv.URL+"/keys", func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, kid := range []string{"r1", "e1"} {
		if _, err := j.Key(ctx, kid); err != nil {
			t.Fatalf("%s: %v", kid, err)
		}
	}
	for _, kid := range []string{"weak", "enc", "private", "missing"} {
		if _, err := j.Key(ctx, kid); !errors.Is(err, errUnknownKid) {
			t.Errorf("%s: %v", kid, err)
		}
	}
	// One fetch, then one refetch for the first miss; later misses within
	// a minute do not refetch.
	if n := fetches.Load(); n != 2 {
		t.Errorf("fetches = %d, want 2", n)
	}
	clock = clock.Add(CacheFor)
	if _, err := j.Key(ctx, "r1"); err != nil || fetches.Load() != 3 {
		t.Errorf("stale cache: %v, fetches %d", err, fetches.Load())
	}
	// Once the cache expired, an unreachable key set fails closed.
	srv.Close()
	clock = clock.Add(CacheFor)
	if _, err := j.Key(ctx, "r1"); err == nil {
		t.Error("an expired cache was used while the key set was unreachable")
	}
	if _, err := NewJWKS(srv.Client(), "https://idp.example.com", "https://other.example.com/keys", nil); err == nil {
		t.Error("a JWKS URI on another host was accepted")
	}
}

// TestJWKSFailedFetchWaitsAMinute: while the key set cannot be fetched,
// pushes do not refetch more than once per MissInterval (D64 L7).
func TestJWKSFailedFetchWaitsAMinute(t *testing.T) {
	var fetches atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	clock := now
	j, err := NewJWKS(srv.Client(), srv.URL, srv.URL+"/keys", func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err := j.Key(context.Background(), "k"); err == nil {
			t.Fatal("a key from a failing key set")
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	clock = clock.Add(MissInterval)
	_, _ = j.Key(context.Background(), "k")
	if n := fetches.Load(); n != 2 {
		t.Fatalf("fetches after a minute = %d, want 2", n)
	}
}

func TestCheckHeaderRefusesBeforeKeys(t *testing.T) {
	f := newFixture(t)
	good := sign(t, jose.RS256, f.rsa, "r1", nil, claimsJSON(nil))
	if err := CheckHeader(good); err != nil {
		t.Fatalf("good header: %v", err)
	}
	for _, bad := range []string{
		"", "junk", rawToken(map[string]any{"alg": "none", "kid": "r1"}, claimsJSON(nil), ""),
		sign(t, jose.RS256, f.rsa, "r1", map[jose.HeaderKey]any{"jku": "https://evil.example/jwks"}, claimsJSON(nil)),
	} {
		if err := CheckHeader(bad); err == nil {
			t.Errorf("accepted header of %q", bad)
		}
	}
}
