// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// boundWorld is a world with an allow-listed MCP client's instance and the
// org's MCP authorization on for gw.example.test.
func boundWorld(t *testing.T) (*world, *boundRig, ports.AccessClaims) {
	t.Helper()
	w := newWorld(t)
	k, err := keys.GenerateSigningKey(keys.PurposeMcpTokens)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.reg.Put(k); err != nil {
		t.Fatal(err)
	}
	agent, inst, client := w.agent(t, adomain.ContextCI), ids.NewV7(), ids.NewV7()
	w.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'mcp_client')`, w.org, inst, agent, "unheld-"+inst.String())
	digest := sha256.Sum256([]byte("doc"))
	w.exec(t, `INSERT INTO pc.mcp_clients (org_id, id, client_url, agent_id, instance_id, state, created_by, activated_at,
		redirect_uris, document_digest) VALUES ($1, $2, 'https://editor.example/c.json', $3, $4, 'ACTIVE', $5, now(), $6, $7)`,
		w.org, client, agent, inst, w.owner, []string{"http://127.0.0.1:4567/cb"}, digest[:])
	w.exec(t, `INSERT INTO pc.org_mcp_access (org_id, enabled, gateway_url, updated_by) VALUES ($1, true, 'https://gw.example.test', $2)`,
		w.org, w.owner)
	r := newBoundRig(t, w.reg, w.org, pap.Instance{Org: w.org, Agent: agent, Instance: inst})
	return w, r, ports.AccessClaims{
		Org: w.org, Environment: w.env, Agent: agent, Instance: inst, Run: ids.NewV7(), Connection: "github",
		Resource: oauthURL, ClientKind: ports.ClientMcp, Client: client, Scope: []string{"tickets.read"},
	}
}

// TestHR700_ABoundTokenWithItsProofIsIdentifiedAsDPoP (G0 M30 D913,
// HR-700): a bound token with a good proof over the call is identified with
// proof "dpop" and its key, while the same token without a proof is
// refused; an unbound token keeps working as a bearer token (FD4).
func TestHR700_ABoundTokenWithItsProofIsIdentifiedAsDPoP(t *testing.T) {
	w, r, claims := boundWorld(t)
	ctx := context.Background()
	bound := r.mint(t, r.jkt, claims)
	n, err := w.svc.Nonce(ctx, w.org)
	if err != nil {
		t.Fatal(err)
	}
	proof := dpopProof(t, r.key, dpopClaims{Method: "POST", URL: oauthURL, Token: bound, Nonce: n, At: time.Now()})
	got, err := w.svc.Identify(ctx, w.org, app.IdentifyInput{Request: pap.Request{Method: "POST", URL: oauthURL, Token: bound}, Proof: proof})
	if err != nil || got.Proof != mcptoken.ProofDPoP || got.JKT != r.jkt || got.Bearer == nil {
		t.Fatalf("a bound call: %+v %v", got, err)
	}
	if _, err := w.svc.Identify(ctx, w.org, app.IdentifyInput{Request: pap.Request{Method: "POST", URL: oauthURL, Token: bound}}); papCode(err) != pap.CodeInvalidToken {
		t.Fatalf("a bound token as bearer: %v", err)
	}
	unbound := r.mint(t, "", claims)
	got, err = w.svc.Identify(ctx, w.org, app.IdentifyInput{Request: pap.Request{Method: "POST", URL: oauthURL, Token: unbound}})
	if err != nil || got.Proof != mcptoken.ProofBearer || got.JKT != "" {
		t.Fatalf("a bearer call: %+v %v", got, err)
	}
}

// TestHR702_AProofNeedsALiveNonceAndIsUsedOnce (G0 M30 D913, HR-702): a
// proof with a live org nonce is accepted once; the same proof again is
// proof_replay, and a well-formed nonce the org never issued is use_nonce.
func TestHR702_AProofNeedsALiveNonceAndIsUsedOnce(t *testing.T) {
	w, r, claims := boundWorld(t)
	ctx := context.Background()
	bound := r.mint(t, r.jkt, claims)
	n, err := w.svc.Nonce(ctx, w.org)
	if err != nil {
		t.Fatal(err)
	}
	in := app.IdentifyInput{Request: pap.Request{Method: "POST", URL: oauthURL, Token: bound},
		Proof: dpopProof(t, r.key, dpopClaims{Method: "POST", URL: oauthURL, Token: bound, Nonce: n, At: time.Now()})}
	if _, err := w.svc.Identify(ctx, w.org, in); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := w.svc.Identify(ctx, w.org, in); papCode(err) != pap.CodeProofReplay {
		t.Fatalf("a replayed proof: %v", err)
	}
	stale := app.IdentifyInput{Request: in.Request,
		Proof: dpopProof(t, r.key, dpopClaims{Method: "POST", URL: oauthURL, Token: bound, Nonce: "never-issued-nonce-0123456789", At: time.Now()})}
	if _, err := w.svc.Identify(ctx, w.org, stale); papCode(err) != pap.CodeUseNonce {
		t.Fatalf("an unknown nonce: %v", err)
	}
}

// TestT320_AStolenBoundTokenIsUselessWithoutTheClientsKey (T-320): a thief
// holding a bound token but not the client's key can neither send it as a
// bearer token, nor sign a proof of their own, nor reuse a proof copied
// from an earlier call; the client's own next call still works.
func TestT320_AStolenBoundTokenIsUselessWithoutTheClientsKey(t *testing.T) {
	w, r, claims := boundWorld(t)
	ctx := context.Background()
	bound := r.mint(t, r.jkt, claims)
	nonce := func() string {
		n, err := w.svc.Nonce(ctx, w.org)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	req := pap.Request{Method: "POST", URL: oauthURL, Token: bound}
	copied := dpopProof(t, r.key, dpopClaims{Method: "POST", URL: oauthURL, Token: bound, Nonce: nonce(), At: time.Now()})
	if _, err := w.svc.Identify(ctx, w.org, app.IdentifyInput{Request: req, Proof: copied}); err != nil {
		t.Fatalf("the client's call: %v", err)
	}
	thief := newBoundRig(t, w.reg, w.org, r.inst)
	for name, proof := range map[string]string{
		"as a bearer token":    "",
		"with the thief's key": dpopProof(t, thief.key, dpopClaims{Method: "POST", URL: oauthURL, Token: bound, Nonce: nonce(), At: time.Now()}),
		"with a copied proof":  copied,
	} {
		if _, err := w.svc.Identify(ctx, w.org, app.IdentifyInput{Request: req, Proof: proof}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := w.svc.Identify(ctx, w.org, app.IdentifyInput{Request: req,
		Proof: dpopProof(t, r.key, dpopClaims{Method: "POST", URL: oauthURL, Token: bound, Nonce: nonce(), At: time.Now()})}); err != nil {
		t.Fatalf("the client's next call: %v", err)
	}
}
