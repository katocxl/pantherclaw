// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// dpopClaims are a DPoP proof's claims (RFC 9449 §4.2) as a client signs
// them; Token sets ath.
type dpopClaims struct {
	Method, URL, Token, Nonce string
	At                        time.Time
	JTI                       string
}

// dpopProof signs a DPoP proof with key, as an RFC 9449 client does.
func dpopProof(t *testing.T, key ed25519.PrivateKey, c dpopClaims) string {
	t.Helper()
	if c.JTI == "" {
		var id [16]byte
		_, _ = rand.Read(id[:])
		c.JTI = base64.RawURLEncoding.EncodeToString(id[:])
	}
	body := map[string]any{"htm": c.Method, "htu": c.URL, "iat": c.At.Unix(), "jti": c.JTI}
	if c.Token != "" {
		sum := sha256.Sum256([]byte(c.Token))
		body["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	if c.Nonce != "" {
		body["nonce"] = c.Nonce
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{
		"typ": pap.DPoPType, "jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// boundRig mints MCP access tokens of one org, bound to a client key or not.
type boundRig struct {
	reg  *keys.Registry
	org  ids.OrgID
	inst pap.Instance
	key  ed25519.PrivateKey
	jkt  string
}

func newBoundRig(t *testing.T, reg *keys.Registry, org ids.OrgID, inst pap.Instance) *boundRig {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	return &boundRig{reg: reg, org: org, inst: inst, key: key, jkt: jws.Thumbprint(pub)}
}

func (r *boundRig) mint(t *testing.T, jkt string, claims ports.AccessClaims) string {
	t.Helper()
	m := &mcptoken.Minter{Keys: mcptoken.SignerFunc(func() (*jws.Signer, error) { return r.reg.Signer(keys.PurposeMcpTokens) }), Issuer: bearerIssuer}
	if claims.Resource == "" {
		claims = ports.AccessClaims{
			Org: r.org, Environment: ids.NewV7(), Agent: r.inst.Agent, Instance: r.inst.Instance, Run: ids.NewV7(), Connection: "github",
			Resource: oauthURL, ClientKind: ports.ClientMcp, Client: ids.NewV7(), Scope: []string{"tickets.read"},
		}
	}
	claims.JKT = jkt
	tok, _, err := m.Mint(context.Background(), claims, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func mcpRegistry(t *testing.T) *keys.Registry {
	t.Helper()
	reg := keys.NewRegistry()
	for _, p := range []keys.Purpose{keys.PurposeWorkloadTokens, keys.PurposeMcpTokens} {
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

func papCode(err error) pap.Code {
	var pe *pap.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// TestHR700_ABoundTokenIsNeverABearerToken (G0 M30 D913, HR-700): an MCP
// token bound to a key (cnf.jkt, pap.proof "dpop") without a DPoP proof is
// refused as invalid_token, as is an unbound token presented with a proof;
// both are refused before anything is read. The token carries both claims
// and the verifier reads it as DPoP-bound (the passing case through the
// database is in bearer_m30_integration_test.go).
func TestHR700_ABoundTokenIsNeverABearerToken(t *testing.T) {
	reg := mcpRegistry(t)
	svc := app.New(nil, reg, bearerIssuer, clock.System{})
	org := ids.New[ids.Org]()
	r := newBoundRig(t, reg, org, pap.Instance{Org: org, Agent: ids.NewV7(), Instance: ids.NewV7()})
	bound, unbound := r.mint(t, r.jkt, ports.AccessClaims{}), r.mint(t, "", ports.AccessClaims{})

	v, err := svc.McpVerifier()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := mcptoken.Verify(v, bearerIssuer, bound, oauthURL, time.Now())
	if err != nil || tok.JKT != r.jkt || tok.Proof != mcptoken.ProofDPoP {
		t.Fatalf("bound token %+v %v", tok, err)
	}

	proof := dpopProof(t, r.key, dpopClaims{Method: "POST", URL: oauthURL, Token: unbound, Nonce: "n-0123456789abcdefghijklmn", At: time.Now()})
	for name, in := range map[string]app.IdentifyInput{
		"a bound token with no proof":   {Request: pap.Request{Method: "POST", URL: oauthURL, Token: bound}},
		"an unbound token with a proof": {Request: pap.Request{Method: "POST", URL: oauthURL, Token: unbound}, Proof: proof},
	} {
		if _, err := svc.Identify(context.Background(), org, in); papCode(err) != pap.CodeInvalidToken {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR702_TheProofAtUseMatchesKeyRequestTokenTimeAndNonce (G0 M30 D913,
// HR-702): a bound token's proof is refused when it is signed by another
// key, names another method or URL, hashes another token, is over 60
// seconds old or carries no nonce (use_nonce), all before the nonce and
// replay store are read. A proof that passes them all is accepted by the
// stateless check (the nonce and single use are in
// bearer_m30_integration_test.go).
func TestHR702_TheProofAtUseMatchesKeyRequestTokenTimeAndNonce(t *testing.T) {
	reg := mcpRegistry(t)
	svc := app.New(nil, reg, bearerIssuer, clock.System{})
	org := ids.New[ids.Org]()
	r := newBoundRig(t, reg, org, pap.Instance{Org: org, Agent: ids.NewV7(), Instance: ids.NewV7()})
	bound, other := r.mint(t, r.jkt, ports.AccessClaims{}), r.mint(t, r.jkt, ports.AccessClaims{})
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	good := dpopClaims{Method: "POST", URL: oauthURL, Token: bound, Nonce: "n-0123456789abcdefghijklmn", At: now}

	if _, err := pap.VerifyDPoP(dpopProof(t, r.key, good), pap.DPoPRequest{Method: "POST", URL: oauthURL, Token: bound}, now); err != nil {
		t.Fatalf("a good proof: %v", err)
	}
	edit := func(f func(*dpopClaims)) dpopClaims { c := good; f(&c); return c }
	for name, tc := range map[string]struct {
		key    ed25519.PrivateKey
		claims dpopClaims
		code   pap.Code
	}{
		"another key":         {otherKey, good, pap.CodeKeyMismatch},
		"another method":      {r.key, edit(func(c *dpopClaims) { c.Method = "GET" }), pap.CodeInvalidProof},
		"another URL":         {r.key, edit(func(c *dpopClaims) { c.URL = "https://gw.example.test/mcp-oauth/slack" }), pap.CodeInvalidProof},
		"another token's ath": {r.key, edit(func(c *dpopClaims) { c.Token = other }), pap.CodeInvalidProof},
		"no ath":              {r.key, edit(func(c *dpopClaims) { c.Token = "" }), pap.CodeInvalidProof},
		"a stale iat":         {r.key, edit(func(c *dpopClaims) { c.At = now.Add(-2 * time.Minute) }), pap.CodeInvalidProof},
		"no nonce":            {r.key, edit(func(c *dpopClaims) { c.Nonce = "" }), pap.CodeUseNonce},
	} {
		_, err := svc.Identify(context.Background(), org, app.IdentifyInput{
			Request: pap.Request{Method: "POST", URL: oauthURL, Token: bound}, Proof: dpopProof(t, tc.key, tc.claims),
		})
		if papCode(err) != tc.code {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
		}
	}
}
