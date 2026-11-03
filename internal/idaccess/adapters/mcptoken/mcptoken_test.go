// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcptoken_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func signer(t *testing.T, kid string) *jws.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.NewSigner(kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const (
	issuer   = "https://pc.example.com"
	resource = "https://gw.example.com/mcp-oauth/github"
)

// TestHR626_McpTokensNeverPassForWorkloadTokens: an MCP token verifies
// only with the mcp_tokens keys at the one server it names; a workload
// token never verifies as one, nor the other way round; an expired token
// and a token for another server are refused.
//
// Covers: F912
func TestHR626_McpTokensNeverPassForWorkloadTokens(t *testing.T) {
	mcpKey, wtKey := signer(t, "mcp-1"), signer(t, "wt-1")
	m := &mcptoken.Minter{Keys: mcptoken.SignerFunc(func() (*jws.Signer, error) { return mcpKey, nil }), Issuer: issuer}
	org := ids.New[ids.Org]()
	c := ports.AccessClaims{
		Org: org, Environment: ids.NewV7(), Agent: ids.NewV7(), Instance: ids.NewV7(), Run: ids.NewV7(), Connection: "github",
		Resource: resource, ClientKind: ports.ClientMcp, Client: ids.NewV7(), Scope: []string{"tickets.read"},
	}
	now := time.Unix(1_800_000_000, 0)
	tok, exp, err := m.Mint(context.Background(), c, now)
	if err != nil || exp.Sub(now) != 5*time.Minute {
		t.Fatalf("mint: %v %v", exp, err)
	}
	mcpV, err := jws.NewVerifier(mcptoken.TokenType, map[string]ed25519.PublicKey{"mcp-1": mcpKey.Public()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := mcptoken.Verify(mcpV, issuer, tok, resource, now)
	if err != nil || got.Run != c.Run || got.Connection != "github" || got.Instance.Org != org || len(got.Operations) != 1 {
		t.Fatalf("verify: %+v %v", got, err)
	}
	refused := map[string]error{}
	_, refused["a token for another server"] = mcptoken.Verify(mcpV, issuer, tok, "https://gw.example.com/mcp-oauth/slack", now)
	_, refused["on a PAP/1 route"] = mcptoken.Verify(mcpV, issuer, tok, "https://gw.example.com/mcp/github", now)
	_, refused["expired"] = mcptoken.Verify(mcpV, issuer, tok, resource, now.Add(6*time.Minute))
	_, refused["another issuer"] = mcptoken.Verify(mcpV, "https://evil.example.com", tok, resource, now)
	for name, err := range refused {
		if !errors.Is(err, mcptoken.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A workload-token verifier refuses an MCP token: another typ and kid.
	wtV, err := jws.NewVerifier(pap.TokenType, map[string]ed25519.PublicKey{"wt-1": wtKey.Public(), "mcp-1": mcpKey.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pap.VerifyToken(wtV, issuer, tok, now); err == nil {
		t.Fatal("an MCP token passed as a workload token")
	}
	// An MCP-typed token signed with a workload key is refused: the mcp
	// verifier knows only mcp_tokens keys.
	wtMinted := &mcptoken.Minter{Keys: mcptoken.SignerFunc(func() (*jws.Signer, error) { return wtKey, nil }), Issuer: issuer}
	forged, _, err := wtMinted.Mint(context.Background(), c, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mcptoken.Verify(mcpV, issuer, forged, resource, now); !errors.Is(err, mcptoken.ErrInvalid) {
		t.Fatalf("a workload-key token passed: %v", err)
	}
	// A workload token is refused by the MCP verifier.
	wt, _, err := pap.Issue(wtKey, issuer, pap.Token{
		Instance: pap.Instance{Org: org, Agent: c.Agent, Instance: c.Instance}, Environment: c.Environment,
		JKT: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", Level: 1,
	}, now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mcptoken.Verify(mcpV, issuer, wt, resource, now); !errors.Is(err, mcptoken.ErrInvalid) {
		t.Fatalf("a workload token passed as an MCP token: %v", err)
	}
}
