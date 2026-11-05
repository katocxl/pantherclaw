// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/sim/google"
)

// testRSAKey is a 2048-bit key in PKCS #8 PEM, as Google issues one.
func testRSAKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

type googleWorld struct {
	sim    *google.Server
	srv    *httptest.Server
	client *egress.Client
	sa     domain.GoogleServiceAccount
	hosts  []string
}

func newGoogle(t *testing.T) *googleWorld {
	t.Helper()
	k, pemKey := testRSAKey(t)
	const email = "agent@simulated-project.iam.gserviceaccount.com"
	sim := google.New(&google.Account{ClientEmail: email, Key: &k.PublicKey}, google.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	c, err := egress.NewClient(srv.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	return &googleWorld{
		sim: sim, srv: srv, client: c, hosts: []string{u.Host},
		sa: domain.GoogleServiceAccount{
			V: 1, ClientEmail: email, PrivateKey: pemKey, TokenURI: srv.URL + "/token", Subject: google.Mailbox,
			Scopes: []string{"https://www.googleapis.com/auth/gmail.readonly"},
		},
	}
}

// claimsOf decodes a JWT's claims without checking it.
func claimsOf(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestHR721_AServiceAccountTokenIsMintedPerDispatchAndTheKeyNeverPlaced: the
// assertion names the account, the delegated user, the token endpoint and
// the sealed scopes and lives five minutes; each dispatch mints a fresh
// token; what is placed is the token, never the key; and the token works
// at the API.
//
// Covers: HR-721
func TestHR721_AServiceAccountTokenIsMintedPerDispatchAndTheKeyNeverPlaced(t *testing.T) {
	w := newGoogle(t)
	key, _ := w.sa.Key()
	now := time.Now()
	jwt, err := serviceAccountJWT(key, w.sa, now)
	if err != nil {
		t.Fatal(err)
	}
	c := claimsOf(t, string(jwt))
	if c["iss"] != w.sa.ClientEmail || c["sub"] != google.Mailbox || c["aud"] != w.sa.TokenURI ||
		c["scope"] != "https://www.googleapis.com/auth/gmail.readonly" || c["exp"].(float64)-c["iat"].(float64) != 300 {
		t.Fatalf("claims %v", c)
	}
	var seen []string
	for range 2 {
		tok, err := MintServiceAccountToken(t.Context(), w.client, w.hosts, w.sa, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, w.srv.URL+"/gmail/v1/users/me/messages", nil)
		if err := tok.Place(req); err != nil {
			t.Fatal(err)
		}
		auth := req.Header.Get("Authorization")
		if auth != "Bearer "+string(tok.Token()) || strings.Contains(auth, "PRIVATE KEY") {
			t.Fatalf("placed %q", auth)
		}
		if res, err := w.client.Do(req); err != nil || res.Status != http.StatusOK {
			t.Fatalf("gmail: %v %v", res, err)
		}
		seen = append(seen, string(tok.Token()))
		tok.Clear()
	}
	if seen[0] == seen[1] || w.sim.Stats().TokensIssued != 2 {
		t.Fatalf("a token was cached: %v, %d issued", seen, w.sim.Stats().TokensIssued)
	}
}

// TestHR721_AServiceAccountMintsOnlyAtABoundGoogleEndpoint: a token
// endpoint the seal does not bind is never sent the assertion; an endpoint
// that is not Google's (nor a loopback simulator's), too few or foreign
// scopes, or a short key make the credential unusable; and a minted token
// is placed on no unbound host.
//
// Covers: HR-721
func TestHR721_AServiceAccountMintsOnlyAtABoundGoogleEndpoint(t *testing.T) {
	w := newGoogle(t)
	if _, err := MintServiceAccountToken(t.Context(), w.client, []string{"www.googleapis.com"}, w.sa, time.Now()); !errors.Is(err, ErrNotBound) {
		t.Fatalf("unbound token endpoint: %v", err)
	}
	if n := w.sim.Stats().Calls["token"]; n != 0 {
		t.Fatalf("the token endpoint was called %d times", n)
	}
	_, short := func() (*rsa.PrivateKey, []byte) {
		k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the short key under test
		if err != nil {
			t.Fatal(err)
		}
		return k, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	}()
	for name, mut := range map[string]func(*domain.GoogleServiceAccount){
		"another endpoint": func(g *domain.GoogleServiceAccount) { g.TokenURI = "https://oauth2.attacker.example/token" },
		"no scope":         func(g *domain.GoogleServiceAccount) { g.Scopes = nil },
		"foreign scope":    func(g *domain.GoogleServiceAccount) { g.Scopes = []string{"https://attacker.example/auth/all"} },
		"short key":        func(g *domain.GoogleServiceAccount) { g.PrivateKey = short },
	} {
		sa := w.sa
		mut(&sa)
		if _, err := MintServiceAccountToken(t.Context(), w.client, w.hosts, sa, time.Now()); !errors.Is(err, domain.ErrGoogleServiceAccount) {
			t.Errorf("%s: %v", name, err)
		}
	}
	prod := w.sa
	prod.TokenURI = domain.GoogleTokenURI
	if err := prod.Validate(); err != nil {
		t.Fatalf("Google's endpoint: %v", err)
	}
	tok, err := MintServiceAccountToken(t.Context(), w.client, w.hosts, w.sa, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://attacker.example/x", nil)
	if err := tok.Place(req); err == nil || req.Header.Get("Authorization") != "" {
		t.Fatalf("placed on an unbound host: %v %q", err, req.Header.Get("Authorization"))
	}
}

// TestHR726_ASnowflakeKeyPairJWTIsSignedPerDispatch: the JWT names
// ACCOUNT.USER and the key's fingerprint, lives at most an hour, is placed
// with the key-pair token type on a bound host only, and never carries the
// private key.
//
// Covers: HR-726
func TestHR726_ASnowflakeKeyPairJWTIsSignedPerDispatch(t *testing.T) {
	k, pemKey := testRSAKey(t)
	kp := domain.SnowflakeKeypair{V: 1, Account: "myorg-acct.us-east-2.aws", User: "agent_reader", PrivateKey: pemKey}
	hosts := []string{"myorg-acct.snowflakecomputing.com"}
	now := time.Now()
	a, err := MintSnowflakeToken(hosts, kp, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MintSnowflakeToken(hosts, kp, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Token()) == string(b.Token()) {
		t.Fatal("a JWT was reused")
	}
	fp, _ := domain.Fingerprint(&k.PublicKey)
	c := claimsOf(t, string(a.Token()))
	if c["sub"] != "MYORG-ACCT.AGENT_READER" || c["iss"] != "MYORG-ACCT.AGENT_READER."+fp || c["exp"].(float64)-c["iat"].(float64) > 3600 {
		t.Fatalf("claims %v", c)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://myorg-acct.snowflakecomputing.com/api/v2/statements", nil)
	if err := a.Place(req); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer "+string(a.Token()) || req.Header.Get(domain.SnowflakeTokenTypeHeader) != domain.SnowflakeTokenTypeKeypair ||
		strings.Contains(req.Header.Get("Authorization"), "PRIVATE KEY") {
		t.Fatalf("placed %v", req.Header)
	}
	other, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://attacker.example/api/v2/statements", nil)
	if err := a.Place(other); err == nil || other.Header.Get("Authorization") != "" {
		t.Fatalf("placed on an unbound host: %v", err)
	}
	kp.Account = "bad account"
	if _, err := MintSnowflakeToken(hosts, kp, now); !errors.Is(err, domain.ErrSnowflakeKeypair) {
		t.Fatalf("a malformed account: %v", err)
	}
}
