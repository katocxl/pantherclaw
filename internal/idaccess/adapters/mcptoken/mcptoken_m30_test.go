// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcptoken_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR700_KeyConfirmationAndProofModeAgree (G0 M30 D912, D913; HR-700):
// a token minted for a key carries cnf.jkt and pap.proof "dpop" and
// verifies as bound; a token whose cnf.jkt and pap.proof disagree, or whose
// cnf.jkt is no thumbprint, is invalid even under a good signature, and
// minting refuses a malformed key.
func TestHR700_KeyConfirmationAndProofModeAgree(t *testing.T) {
	key := signer(t, "mcp-1")
	m := &mcptoken.Minter{Keys: mcptoken.SignerFunc(func() (*jws.Signer, error) { return key, nil }), Issuer: issuer}
	v, err := jws.NewVerifier(mcptoken.TokenType, map[string]ed25519.PublicKey{"mcp-1": key.Public()})
	if err != nil {
		t.Fatal(err)
	}
	const jkt = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	c := ports.AccessClaims{
		Org: ids.New[ids.Org](), Environment: ids.NewV7(), Agent: ids.NewV7(), Instance: ids.NewV7(), Run: ids.NewV7(), Connection: "github",
		Resource: resource, ClientKind: ports.ClientMcp, Client: ids.NewV7(), Scope: []string{"tickets.read"}, JKT: jkt,
	}
	now := time.Unix(1_800_000_000, 0)
	tok, _, err := m.Mint(context.Background(), c, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mcptoken.Verify(v, issuer, tok, resource, now)
	if err != nil || got.JKT != jkt || got.Proof != mcptoken.ProofDPoP {
		t.Fatalf("bound: %+v %v", got, err)
	}

	resign := func(edit func(map[string]any)) string {
		t.Helper()
		b, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
		var claims map[string]any
		if err := json.Unmarshal(b, &claims); err != nil {
			t.Fatal(err)
		}
		edit(claims)
		payload, _ := json.Marshal(claims)
		s, err := key.Sign(mcptoken.TokenType, payload)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	papOf := func(c map[string]any) map[string]any { p, _ := c["pap"].(map[string]any); return p }
	for name, forged := range map[string]string{
		"cnf without proof dpop": resign(func(c map[string]any) { papOf(c)["proof"] = "bearer" }),
		"proof dpop without cnf": resign(func(c map[string]any) { delete(c, "cnf") }),
		"a cnf that is no key":   resign(func(c map[string]any) { c["cnf"] = map[string]any{"jkt": "short"} }),
	} {
		if _, err := mcptoken.Verify(v, issuer, forged, resource, now); !errors.Is(err, mcptoken.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c.JKT = "not a thumbprint"
	if _, _, err := m.Mint(context.Background(), c, now); err == nil {
		t.Fatal("minted for a malformed key")
	}
}
