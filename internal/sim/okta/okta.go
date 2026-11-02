// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package okta is a simulated enterprise identity provider issuing Identity
// Assertion JWT Authorization Grants (ID-JAG) the way Okta Cross App Access
// does, for tests and demos (pantherclaw-sim okta, G0 M26 D400, D403). It
// follows draft-ietf-oauth-identity-assertion-authz-grant-06:
//
//   - discovery at /.well-known/oauth-authorization-server and
//     /.well-known/openid-configuration, keys at /oauth2/v1/keys (RS256);
//   - POST /oauth2/v1/token, the RFC 8693 token exchange of §4.3: an ID
//     token this simulator issued (subject_token_type id_token) for
//     requested_token_type urn:ietf:params:oauth:token-type:id-jag, with
//     audience (the resource authorization server's issuer), resource and
//     scope; the answer's access_token is the ID-JAG and its token_type
//     N_A;
//   - POST /__sim/sign-in (sub, client_id) returns an ID token for a person,
//     standing in for a real sign-in.
//
// Faults make the next assertions expired, addressed to another audience,
// or carry a cnf claim. Every response is marked SIMULATED; nothing here
// reaches Okta.
package okta

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Token and grant type URIs (RFC 8693, draft -06 §4.3).
const (
	GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TypeIDJAG          = "urn:ietf:params:oauth:token-type:id-jag"
	TypeIDToken        = "urn:ietf:params:oauth:token-type:id_token"
	// JAGType is the JWS typ of an ID-JAG.
	JAGType = "oauth-id-jag+jwt"
	// KeyID names the simulator's signing key.
	KeyID = "sim-okta-1"
	// Lifetime is how long an ID-JAG lives.
	Lifetime = 5 * time.Minute
)

// Faults change the assertions the simulator issues.
type Faults struct {
	// Expired issues assertions that expired a minute ago.
	Expired bool
	// WrongAudience addresses assertions to another authorization server.
	WrongAudience bool
	// Cnf adds a cnf claim, which the resource server must refuse.
	Cnf bool
}

// Sim is the simulated identity provider.
type Sim struct {
	issuer string
	key    *rsa.PrivateKey
	log    *slog.Logger

	mu     sync.Mutex
	faults Faults
	issued int
}

// New returns a simulator whose issuer identifier is issuer (its base URL).
func New(issuer string, faults Faults, log *slog.Logger) (*Sim, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Sim{issuer: strings.TrimSuffix(issuer, "/"), key: key, log: log, faults: faults}, nil
}

// Issuer is the simulator's issuer identifier.
func (s *Sim) Issuer() string { return s.issuer }

// SetFaults replaces the faults (tests).
func (s *Sim) SetFaults(f Faults) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = f
}

// Issued reports how many ID-JAGs were issued.
func (s *Sim) Issued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issued
}

// Assertion is what an ID-JAG says.
type Assertion struct {
	Subject, ClientID, Audience string
	Resource                    []string
	Scope                       string
	Tenant                      string
	// Extra claims are added as they are (tests).
	Extra map[string]any
}

// Assert signs an ID-JAG for a, applying the faults.
func (s *Sim) Assert(a Assertion, now time.Time) (string, error) {
	s.mu.Lock()
	f := s.faults
	s.issued++
	s.mu.Unlock()
	iat, exp := now.Unix(), now.Add(Lifetime).Unix()
	if f.Expired {
		iat, exp = now.Add(-2*time.Minute).Unix(), now.Add(-time.Minute).Unix()
	}
	aud := a.Audience
	if f.WrongAudience {
		aud = strings.TrimSuffix(aud, "/") + "-other"
	}
	c := map[string]any{
		"iss": s.issuer, "sub": a.Subject, "aud": aud, "client_id": a.ClientID, "jti": ids.NewV7().String(),
		"iat": iat, "exp": exp, "auth_time": iat,
	}
	if len(a.Resource) == 1 {
		c["resource"] = a.Resource[0]
	} else if len(a.Resource) > 1 {
		c["resource"] = a.Resource
	}
	if a.Scope != "" {
		c["scope"] = a.Scope
	}
	if a.Tenant != "" {
		c["tenant"] = a.Tenant
	}
	if f.Cnf {
		c["cnf"] = map[string]string{"jkt": "SIMULATED"}
	}
	maps.Copy(c, a.Extra)
	return s.sign(JAGType, c)
}

func (s *Sim) sign(typ string, claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: s.key, KeyID: KeyID}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(b)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// Handler serves the simulator.
func (s *Sim) Handler() http.Handler {
	mux := http.NewServeMux()
	meta := func(w http.ResponseWriter, _ *http.Request) {
		write(w, http.StatusOK, map[string]any{
			"issuer": s.issuer, "jwks_uri": s.issuer + "/oauth2/v1/keys", "token_endpoint": s.issuer + "/oauth2/v1/token",
			"grant_types_supported":                             []string{GrantTokenExchange},
			"identity_chaining_requested_token_types_supported": []string{TypeIDJAG},
			"id_token_signing_alg_values_supported":             []string{"RS256"},
		})
	}
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", meta)
	mux.HandleFunc("GET /.well-known/openid-configuration", meta)
	mux.HandleFunc("GET /oauth2/v1/keys", func(w http.ResponseWriter, _ *http.Request) {
		write(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.key.PublicKey, KeyID: KeyID, Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /__sim/sign-in", s.signIn)
	mux.HandleFunc("POST /oauth2/v1/token", s.token)
	return handshake.Wrap("okta", mux)
}

// signIn issues an ID token for sub at client_id (a stand-in for a sign-in).
func (s *Sim) signIn(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("sub") == "" || r.PostForm.Get("client_id") == "" {
		write(w, http.StatusBadRequest, oauthErr("invalid_request"))
		return
	}
	now := time.Now()
	tok, err := s.sign("JWT", map[string]any{
		"iss": s.issuer, "sub": r.PostForm.Get("sub"), "aud": r.PostForm.Get("client_id"), "iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(), "jti": ids.NewV7().String(),
	})
	if err != nil {
		write(w, http.StatusInternalServerError, oauthErr("server_error"))
		return
	}
	write(w, http.StatusOK, map[string]any{"id_token": tok, "token_type": "N_A"})
}

// token is the draft -06 §4.3 token exchange.
func (s *Sim) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		write(w, http.StatusBadRequest, oauthErr("invalid_request"))
		return
	}
	f := r.PostForm
	if f.Get("grant_type") != GrantTokenExchange || f.Get("requested_token_type") != TypeIDJAG ||
		f.Get("subject_token_type") != TypeIDToken || f.Get("audience") == "" || f.Get("client_id") == "" {
		write(w, http.StatusBadRequest, oauthErr("invalid_request"))
		return
	}
	obj, err := jose.ParseSignedCompact(f.Get("subject_token"), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		write(w, http.StatusBadRequest, oauthErr("invalid_grant"))
		return
	}
	payload, err := obj.Verify(&s.key.PublicKey)
	var id struct {
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
	}
	if err != nil || json.Unmarshal(payload, &id) != nil || id.Aud != f.Get("client_id") || time.Now().Unix() >= id.Exp {
		write(w, http.StatusBadRequest, oauthErr("invalid_grant"))
		return
	}
	var resources []string
	if res := f.Get("resource"); res != "" {
		resources = strings.Fields(res)
	}
	jag, err := s.Assert(Assertion{
		Subject: id.Sub, ClientID: f.Get("client_id"), Audience: f.Get("audience"), Resource: resources, Scope: f.Get("scope"),
	}, time.Now())
	if err != nil {
		write(w, http.StatusInternalServerError, oauthErr("server_error"))
		return
	}
	if s.log != nil {
		s.log.Info("sim.okta_id_jag_issued", slog.String("sub", id.Sub), slog.String("client_id", f.Get("client_id")))
	}
	write(w, http.StatusOK, map[string]any{
		"access_token": jag, "issued_token_type": TypeIDJAG, "token_type": "N_A", "expires_in": int(Lifetime.Seconds()),
	})
}

func oauthErr(code string) map[string]any {
	return map[string]any{"error": code, "error_description": "SIMULATED: " + code}
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}
