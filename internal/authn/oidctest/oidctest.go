// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package oidctest is an in-process OpenID provider for tests: discovery,
// JWKS, an authorization endpoint that signs in a configurable user at
// once, and a token endpoint that checks the client secret, the redirect URI
// and PKCE. Knobs make it misbehave (wrong aud/iss/nonce, alg none, HS256,
// expired tokens, missing iss parameter) to test the relying party.
package oidctest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// User is who the provider signs in.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Knobs make the provider misbehave. The zero value is a correct provider.
type Knobs struct {
	Alg           string // "none" or "HS256" (keyed with the RSA modulus) to forge
	Audience      []string
	Issuer        string
	Nonce         string
	AZP           string
	Expired       bool
	OmitIssParam  bool   // leave iss out of the authorization response
	WrongIssParam string // send this iss in the authorization response
	NoIssSupport  bool   // do not advertise RFC 9207
	Error         string // return this error instead of a code
	// AuthTime, when set, is sent as auth_time. Otherwise auth_time is the
	// time of the authorization when max_age was requested, and absent
	// when it was not (unless OmitAuthTime).
	AuthTime     time.Time
	OmitAuthTime bool
	// TokenAuthPost makes the token endpoint take the client secret only
	// as client_secret_post form fields (and refuse HTTP Basic).
	TokenAuthPost bool
}

// Provider is a running test provider.
type Provider struct {
	*httptest.Server
	ClientID, ClientSecret string

	key *rsa.PrivateKey

	mu    sync.Mutex
	user  User
	knobs Knobs
	codes map[string]grant
}

type grant struct {
	nonce, challenge, redirect, maxAge string
	user                               User
	at                                 time.Time
}

// New starts a provider; it is closed when the test ends.
func New(t testing.TB) *Provider {
	t.Helper()
	return NewWithKeyBits(t, 2048)
}

// NewWithKeyBits starts a provider whose RSA signing key has bits bits
// (FIPS mode refuses keys under 2048 bits, G0 M13 D35).
func NewWithKeyBits(t testing.TB, bits int) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{ClientID: "pantherclaw", ClientSecret: "test-secret", key: key, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	p.user = User{Subject: "user-1", Email: "user1@example.test", EmailVerified: true, Name: "User One"}
	return p
}

// Issuer is the provider's issuer identifier.
func (p *Provider) Issuer() string { return p.URL }

// SignIn sets the user the next authorization signs in.
func (p *Provider) SignIn(u User) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.user = u
}

// Set replaces the knobs.
func (p *Provider) Set(k Knobs) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.knobs = k
}

func (p *Provider) state() (User, Knobs) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.user, p.knobs
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	_, k := p.state()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token",
		"jwks_uri": p.URL + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": !k.NoIssSupport,
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || redirect == "" || !strings.Contains(q.Get("scope"), "openid") {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	u, k := p.state()
	back := url.Values{"state": {q.Get("state")}}
	switch {
	case k.WrongIssParam != "":
		back.Set("iss", k.WrongIssParam)
	case !k.OmitIssParam:
		back.Set("iss", p.URL)
	}
	if k.Error != "" {
		back.Set("error", k.Error)
	} else {
		code := rand.Text()
		p.mu.Lock()
		p.codes[code] = grant{
			nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: redirect, maxAge: q.Get("max_age"), user: u, at: time.Now(),
		}
		p.mu.Unlock()
		back.Set("code", code)
	}
	http.Redirect(w, r, redirect+"?"+back.Encode(), http.StatusFound) //nolint:gosec // G710: a test provider redirects to the client-supplied redirect_uri by design
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id, secret, ok := r.BasicAuth()
	if _, k := p.state(); k.TokenAuthPost {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		ok = !hasBasic(r) && id != "" && secret != ""
	}
	if !ok || id != p.ClientID || secret != p.ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	p.mu.Lock()
	g, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || r.PostForm.Get("redirect_uri") != g.redirect || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": rand.Text(), "token_type": "Bearer", "expires_in": 300, "id_token": p.idToken(g),
	})
}

func hasBasic(r *http.Request) bool {
	_, _, ok := r.BasicAuth()
	return ok
}

func (p *Provider) idToken(g grant) string {
	_, k := p.state()
	now := time.Now()
	claims := map[string]any{
		"iss": p.URL, "sub": g.user.Subject, "aud": []string{p.ClientID}, "nonce": g.nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"email": g.user.Email, "email_verified": g.user.EmailVerified, "name": g.user.Name,
	}
	if k.Issuer != "" {
		claims["iss"] = k.Issuer
	}
	if k.Audience != nil {
		claims["aud"] = k.Audience
	}
	if k.Nonce != "" {
		claims["nonce"] = k.Nonce
	}
	if k.AZP != "" {
		claims["azp"] = k.AZP
	}
	switch {
	case !k.AuthTime.IsZero():
		claims["auth_time"] = k.AuthTime.Unix()
	case g.maxAge != "" && !k.OmitAuthTime:
		claims["auth_time"] = g.at.Unix()
	}
	if k.Expired {
		claims["iat"], claims["exp"] = now.Add(-time.Hour).Unix(), now.Add(-30*time.Minute).Unix()
	}
	payload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	switch k.Alg {
	case "none":
		// Test support: forges an unsigned token so tests prove it is rejected (HR-095).
		return enc([]byte(`{"alg":"none","kid":"k1"}`)) + "." + enc(payload) + "." // nosemgrep: tools.semgrep.pc-jose-alg-none
	case "HS256":
		head := enc([]byte(`{"alg":"HS256","kid":"k1"}`)) + "." + enc(payload)
		mac := hmac.New(sha256.New, p.key.N.Bytes())
		mac.Write([]byte(head))
		return head + "." + enc(mac.Sum(nil))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		panic(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}

// Token signs claims with the provider's key (RS256, kid k1), with the JWS
// typ header when typ is not empty: for subject tokens (HR-145).
func (p *Provider) Token(claims map[string]any, typ string) string {
	opts := (&jose.SignerOptions{}).WithHeader("kid", "k1")
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, opts)
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}
