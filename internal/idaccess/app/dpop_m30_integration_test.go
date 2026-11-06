// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/idaccess/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

const tokenEndpoint = publicURL + authnapp.TokenPath

// dpopKey is a client's DPoP key.
type dpopKey struct {
	priv ed25519.PrivateKey
	jkt  string
}

func newDPoPKey() dpopKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return dpopKey{priv: priv, jkt: jws.Thumbprint(pub)}
}

// proof signs a token-endpoint DPoP proof (RFC 9449 §4.2: no ath, no nonce).
func (k dpopKey) proof(t *testing.T, htu string) string {
	t.Helper()
	var id [16]byte
	_, _ = rand.Read(id[:])
	payload, _ := json.Marshal(map[string]any{"htm": "POST", "htu": htu, "iat": time.Now().Unix(), "jti": base64.RawURLEncoding.EncodeToString(id[:])})
	pub, _ := k.priv.Public().(ed25519.PublicKey)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: k.priv}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{
		"typ": pap.DPoPType, "jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := obj.CompactSerialize()
	return c
}

func withProof(proofs ...string) context.Context {
	if len(proofs) == 0 {
		return context.Background()
	}
	return authnapp.WithDPoP(context.Background(), proofs)
}

func redeemWith(ctx context.Context, flow *app.CodeFlow, code string) (authnapp.TokenResponse, error) {
	return flow.AuthorizationCode(ctx, url.Values{
		"grant_type": {app.GrantAuthorizationCode}, "code": {code}, "client_id": {mcpClient}, "redirect_uri": {mcpRedirect},
		"code_verifier": {verifier}, "resource": {resource},
	})
}

func refreshWith(ctx context.Context, flow *app.CodeFlow, token string) (authnapp.TokenResponse, error) {
	return flow.Refresh(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {mcpClient}})
}

// cnfOf reads an access token's cnf.jkt and pap.proof, unverified.
func cnfOf(t *testing.T, tok string) (string, string) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", tok)
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Cnf struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
		PAP struct {
			Proof string `json:"proof"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c.Cnf.JKT, c.PAP.Proof
}

const invalidDPoP = "invalid_dpop_proof"

func isInvalidDPoP(err error) bool { return strings.HasPrefix(oauthCode(err), invalidDPoP+" ") }

// TestHR701_TheTokenEndpointBindsFromAValidProof (G0 M30 D912, HR-701): a
// valid proof gets a DPoP token whose cnf.jkt is the proof's key, and the
// issuance is audited as bound; its refresh token refreshes only with a
// proof of that key. No proof keeps the 5-minute bearer token (FD4).
func TestHR701_TheTokenEndpointBindsFromAValidProof(t *testing.T) {
	e, flow, _ := codeEnv(t)
	k := newDPoPKey()
	res, err := redeemWith(withProof(k.proof(t, tokenEndpoint)), flow, codeOf(t, mustApprove(t, flow, e)))
	if err != nil || res.TokenType != "DPoP" {
		t.Fatalf("a bound redeem: %+v %v", res, err)
	}
	if jkt, proof := cnfOf(t, res.AccessToken); jkt != k.jkt || proof != "dpop" {
		t.Fatalf("cnf %q proof %q", jkt, proof)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.idaccess.token_issued'
		AND convert_from(body, 'UTF8')::jsonb #>> '{details,binding}' = 'dpop'`, e.org); n != 1 {
		t.Fatalf("bound issuance audits: %d", n)
	}
	next, err := refreshWith(withProof(k.proof(t, tokenEndpoint)), flow, res.RefreshToken)
	if err != nil || next.TokenType != "DPoP" {
		t.Fatalf("a bound refresh: %+v %v", next, err)
	}
	if jkt, _ := cnfOf(t, next.AccessToken); jkt != k.jkt {
		t.Fatalf("refreshed cnf %q", jkt)
	}

	plain, err := redeemWith(withProof(), flow, codeOf(t, mustApprove(t, flow, e)))
	if err != nil || plain.TokenType != "Bearer" || plain.ExpiresIn > 300 {
		t.Fatalf("a bearer redeem: %+v %v", plain, err)
	}
	if jkt, proof := cnfOf(t, plain.AccessToken); jkt != "" || proof != "bearer" {
		t.Fatalf("bearer cnf %q proof %q", jkt, proof)
	}
}

// TestHR701_TheTokenEndpointRefusesWhatABindingCannotTrust (G0 M30 D912,
// HR-701): a proof for another URL, a proof used twice, two DPoP headers, a
// bound refresh token without a proof or with another key, a code issued
// for a dpop_jkt redeemed with another key, and a client that asks for bound
// tokens redeeming without a proof are all invalid_dpop_proof.
func TestHR701_TheTokenEndpointRefusesWhatABindingCannotTrust(t *testing.T) {
	e, flow, client := codeEnv(t)
	k, other := newDPoPKey(), newDPoPKey()

	if _, err := redeemWith(withProof(k.proof(t, publicURL+"/other")), flow, codeOf(t, mustApprove(t, flow, e))); !isInvalidDPoP(err) {
		t.Errorf("a proof for another URL: %s", oauthCode(err))
	}
	if _, err := redeemWith(withProof("a.b.c", "d.e.f"), flow, codeOf(t, mustApprove(t, flow, e))); !isInvalidDPoP(err) {
		t.Errorf("two proofs: %s", oauthCode(err))
	}
	used := k.proof(t, tokenEndpoint)
	res, err := redeemWith(withProof(used), flow, codeOf(t, mustApprove(t, flow, e)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redeemWith(withProof(used), flow, codeOf(t, mustApprove(t, flow, e))); !isInvalidDPoP(err) {
		t.Errorf("a replayed proof: %s", oauthCode(err))
	}
	if _, err := refreshWith(withProof(), flow, res.RefreshToken); !isInvalidDPoP(err) {
		t.Errorf("a bound refresh without a proof: %s", oauthCode(err))
	}
	res, err = redeemWith(withProof(k.proof(t, tokenEndpoint)), flow, codeOf(t, mustApprove(t, flow, e)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refreshWith(withProof(other.proof(t, tokenEndpoint)), flow, res.RefreshToken); !isInvalidDPoP(err) {
		t.Errorf("a bound refresh with another key: %s", oauthCode(err))
	}

	// A code issued for a key (RFC 9449 §10) needs that key.
	r, err := flow.Approve(context.Background(), e.org, e.user, authorizeQuery(func(q url.Values) { q.Set("dpop_jkt", k.jkt) }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redeemWith(withProof(other.proof(t, tokenEndpoint)), flow, codeOf(t, r)); !isInvalidDPoP(err) {
		t.Errorf("a dpop_jkt code with another key: %s", oauthCode(err))
	}
	r, err = flow.Approve(context.Background(), e.org, e.user, authorizeQuery(func(q url.Values) { q.Set("dpop_jkt", k.jkt) }))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := redeemWith(withProof(k.proof(t, tokenEndpoint)), flow, codeOf(t, r)); err != nil || got.TokenType != "DPoP" {
		t.Errorf("a dpop_jkt code with its key: %+v %s", got, oauthCode(err))
	}

	// A client whose document asks for bound tokens gets none without a proof.
	e.exec(t, "UPDATE pc.mcp_clients SET dpop_bound = true WHERE id = $1", client)
	if _, err := redeemWith(withProof(), flow, codeOf(t, mustApprove(t, flow, e))); !isInvalidDPoP(err) {
		t.Errorf("a bound client without a proof: %s", oauthCode(err))
	}
	if n := e.count(t, "SELECT count(*) FROM pc.mcp_refresh_tokens WHERE org_id = $1 AND dpop_jkt IS NOT NULL AND dpop_jkt <> $2", e.org, k.jkt); n != 0 {
		t.Errorf("%d refresh tokens bound to another key", n)
	}
}
