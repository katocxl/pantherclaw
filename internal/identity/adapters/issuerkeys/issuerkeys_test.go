// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuerkeys_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type issuer struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	jwksHits  atomic.Int32
	jwksURI   string
	jwksExtra string
}

func newIssuer(t *testing.T, bits int) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{key: key}
	mux := http.NewServeMux()
	is.srv = httptest.NewTLSServer(mux)
	t.Cleanup(is.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		uri := is.jwksURI
		if uri == "" {
			uri = is.srv.URL + "/jwks"
		}
		_, _ = w.Write([]byte(`{"issuer":"` + is.srv.URL + `","jwks_uri":"` + uri + `"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		is.jwksHits.Add(1)
		e := big.NewInt(int64(key.E)).Bytes()
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"` + b64(key.N.Bytes()) +
			`","e":"` + b64(e) + `"}` + is.jwksExtra + `]}`))
	})
	return is
}

// token signs header and payload JSON with RS256.
func (is *issuer) token(t *testing.T, header string) string {
	t.Helper()
	signing := b64([]byte(header)) + "." + b64([]byte(`{"iss":"x","repository_id":"1"}`))
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, is.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func (is *issuer) client(allowLoopback bool) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(is.srv.Certificate())
	cfg := httpx.EgressConfig{RootCAs: pool}
	if allowLoopback {
		cfg.AllowedPrefixes = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	}
	return httpx.NewEgressClient(cfg)
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newFetcher(t *testing.T, is *issuer, clk *fakeClock, allow bool) *issuerkeys.Fetcher {
	t.Helper()
	f, err := issuerkeys.New(is.client(allow), is.srv.URL, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

const goodHeader = `{"typ":"JWT","alg":"RS256","x5t":"abc","kid":"k1"}`

// TestHR142_KeysComeFromTheIssuerOnlyThroughEgressGuards.
func TestHR142_KeysComeFromTheIssuerOnlyThroughEgressGuards(t *testing.T) {
	is := newIssuer(t, 2048)
	clk := &fakeClock{t: time.Unix(1791457200, 0)}
	f := newFetcher(t, is, clk, true)
	ctx := context.Background()
	payload, err := f.Verify(ctx, is.token(t, goodHeader))
	if err != nil || !strings.Contains(string(payload), "repository_id") {
		t.Fatalf("valid token: %s, %v", payload, err)
	}
	for name, h := range map[string]string{
		"embedded jwk":   `{"alg":"RS256","kid":"k1","jwk":{"kty":"RSA"}}`,
		"jku":            `{"alg":"RS256","kid":"k1","jku":"https://evil.test/jwks"}`,
		"x5c":            `{"alg":"RS256","kid":"k1","x5c":["MII"]}`,
		"crit":           `{"alg":"RS256","kid":"k1","crit":["exp"]}`,
		"alg none":       `{"alg":"none","kid":"k1"}`,
		"HS256":          `{"alg":"HS256","kid":"k1"}`,
		"no kid":         `{"alg":"RS256"}`,
		"duplicate alg":  `{"alg":"RS256","alg":"none","kid":"k1"}`,
		"other kid lies": `{"alg":"RS256","kid":"k2"}`,
	} {
		if _, err := f.Verify(ctx, is.token(t, h)); !errors.Is(err, issuerkeys.ErrUnverified) && err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// Unknown kids refetch at most once a minute; the cache lasts 15 minutes.
	hits := is.jwksHits.Load()
	unknown := is.token(t, `{"alg":"RS256","kid":"rotated"}`)
	_, _ = f.Verify(ctx, unknown)
	_, _ = f.Verify(ctx, unknown)
	if got := is.jwksHits.Load() - hits; got > 1 {
		t.Fatalf("%d refetches within a minute, want at most 1", got)
	}
	clk.t = clk.t.Add(61 * time.Second)
	_, _ = f.Verify(ctx, unknown)
	clk.t = clk.t.Add(issuerkeys.CacheFor)
	before := is.jwksHits.Load()
	if _, err := f.Verify(ctx, is.token(t, goodHeader)); err != nil || is.jwksHits.Load() != before+1 {
		t.Fatalf("expired cache was not refreshed (%v)", err)
	}
	// An unreachable issuer fails closed once the cache has expired.
	is.srv.Close()
	clk.t = clk.t.Add(issuerkeys.CacheFor)
	if _, err := f.Verify(ctx, is.token(t, goodHeader)); err == nil {
		t.Fatal("an unreachable issuer verified a token from an expired cache")
	}
}

func TestHR142_KeySourcesAreConstrained(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(1791457200, 0)}
	// A private address is refused unless explicitly allowed.
	is := newIssuer(t, 2048)
	if _, err := newFetcher(t, is, clk, false).Verify(ctx, is.token(t, goodHeader)); err == nil {
		t.Error("fetched keys from a loopback address without an allowed prefix")
	}
	// The JWKS must live on the issuer's own host.
	other := newIssuer(t, 2048)
	other.jwksURI = "https://evil.test/jwks"
	if _, err := newFetcher(t, other, clk, true).Verify(ctx, other.token(t, goodHeader)); err == nil {
		t.Error("followed a JWKS URI on another host")
	}
	// Keys under 2048 bits are ignored.
	weak := newIssuer(t, 1024)
	if _, err := newFetcher(t, weak, clk, true).Verify(ctx, weak.token(t, goodHeader)); err == nil {
		t.Error("accepted a 1024-bit key")
	}
	// Oversized key documents are refused.
	big := newIssuer(t, 2048)
	big.jwksExtra = strings.Repeat(`,{"kty":"oct","k":"`+strings.Repeat("A", 1000)+`"}`, 80)
	if _, err := newFetcher(t, big, clk, true).Verify(ctx, big.token(t, goodHeader)); err == nil {
		t.Error("accepted a JWKS over 64 KiB")
	}
	// Redirects are not followed.
	redirect := httptest.NewTLSServer(http.RedirectHandler("https://evil.test/", http.StatusFound))
	defer redirect.Close()
	pool := x509.NewCertPool()
	pool.AddCert(redirect.Certificate())
	f, _ := issuerkeys.New(httpx.NewEgressClient(httpx.EgressConfig{
		RootCAs: pool, AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}), redirect.URL, clk.now)
	if _, err := f.Verify(ctx, is.token(t, goodHeader)); err == nil {
		t.Error("followed a redirect")
	}
	if _, err := issuerkeys.New(http.DefaultClient, "http://token.actions.githubusercontent.com", nil); err == nil { //nolint:forbidigo // the client is never used
		t.Error("accepted an http issuer")
	}
}

// ecToken signs header and payload with ES256 (raw r||s).
func ecToken(t *testing.T, key *ecdsa.PrivateKey, header string) string {
	t.Helper()
	signing := b64([]byte(header)) + "." + b64([]byte(`{"sub":"spiffe://example.org/agent"}`))
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64(sig)
}

func ecJWKS(key *ecdsa.PrivateKey, kid, use string) string {
	x, y := make([]byte, 32), make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	return `{"kty":"EC","crv":"P-256","kid":"` + kid + `","use":"` + use + `","x":"` + b64(x) + `","y":"` + b64(y) + `"}`
}

// TestHR142_PresetsChooseAlgorithmsUsesAndKeySources: the preset, never the
// token, decides the algorithms, key uses and header members (D118); a
// static key set is never fetched and a pinned JWKS URL replaces discovery.
// Covers: PN-002.3
func TestHR142_PresetsChooseAlgorithmsUsesAndKeySources(t *testing.T) {
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	static := []byte(`{"spiffe_sequence":3,"keys":[` + ecJWKS(key, "j1", "jwt-svid") + `,` + ecJWKS(other, "x1", "x509-svid") + `]}`)
	spiffe := issuerkeys.Config{
		StaticJWKS: static, Algorithms: []string{"ES256", "RS256"}, Uses: []string{"jwt-svid"},
		Header: []string{"alg", "kid", "typ"}, Types: []string{"JWT", "JOSE"},
	}
	f, err := issuerkeys.NewFetcher(nil, spiffe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Verify(ctx, ecToken(t, key, `{"alg":"ES256","kid":"j1","typ":"JWT"}`)); err != nil {
		t.Fatalf("ES256 with a jwt-svid key: %v", err)
	}
	for name, tok := range map[string]string{
		"x509-svid key":       ecToken(t, other, `{"alg":"ES256","kid":"x1"}`),
		"typ not allowed":     ecToken(t, key, `{"alg":"ES256","kid":"j1","typ":"at+jwt"}`),
		"x5t not allowed":     ecToken(t, key, `{"alg":"ES256","kid":"j1","x5t":"abc"}`),
		"RS256 on an EC key":  ecToken(t, key, `{"alg":"RS256","kid":"j1"}`),
		"ES384 not in preset": ecToken(t, key, `{"alg":"ES384","kid":"j1"}`),
		"wrong key under kid": ecToken(t, other, `{"alg":"ES256","kid":"j1"}`),
	} {
		if _, err := f.Verify(ctx, tok); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// A sig-only preset ignores jwt-svid keys; a set with no usable key is refused.
	if _, err := issuerkeys.NewFetcher(nil, issuerkeys.Config{StaticJWKS: static, Algorithms: []string{"ES256"}}, nil); err == nil {
		t.Error("a sig preset accepted a set holding only SPIFFE keys")
	}
	if _, err := issuerkeys.NewFetcher(nil, issuerkeys.Config{StaticJWKS: static, Algorithms: []string{"HS256"}}, nil); err == nil {
		t.Error("accepted a symmetric algorithm")
	}
	if _, err := issuerkeys.NewFetcher(nil, issuerkeys.Config{JWKSURL: "http://www.googleapis.com/oauth2/v3/certs"}, nil); err == nil {
		t.Error("accepted an http JWKS URL")
	}

	// A pinned JWKS URL is fetched directly, with no discovery document.
	is := newIssuer(t, 2048)
	clk := &fakeClock{t: time.Unix(1791457200, 0)}
	pinned, err := issuerkeys.NewFetcher(is.client(true), issuerkeys.Config{JWKSURL: is.srv.URL + "/jwks"}, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pinned.Verify(ctx, is.token(t, goodHeader)); err != nil || is.jwksHits.Load() != 1 {
		t.Fatalf("pinned JWKS URL: %v (%d fetches)", err, is.jwksHits.Load())
	}
	// It is still fetched only through the egress guards.
	guarded, _ := issuerkeys.NewFetcher(is.client(false), issuerkeys.Config{JWKSURL: is.srv.URL + "/jwks"}, clk.now)
	if _, err := guarded.Verify(ctx, is.token(t, goodHeader)); err == nil {
		t.Error("fetched a pinned JWKS from a loopback address without an allowed prefix")
	}
}
