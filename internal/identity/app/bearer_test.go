// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

const (
	bearerIssuer = "https://pc.example.test"
	oauthURL     = "https://gw.example.test/mcp-oauth/github"
	papURL       = "https://gw.example.test/mcp/github"
)

// TestHR626_BearerModeComesFromTheTokenTypeAlone (G0 M26 D408, HR-626):
// the Authority picks bearer mode from the token's type, never from a
// missing proof. A workload token without its proof, a workload token on
// the OAuth route, an MCP token on a PAP/1 route or with a proof, an MCP
// token for another server, an expired one, one of another org and one
// signed with a workload-token key are all refused before anything is
// read. Covers: F912
func TestHR626_BearerModeComesFromTheTokenTypeAlone(t *testing.T) {
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
	svc := app.New(nil, reg, bearerIssuer, clock.System{})
	org, now := ids.New[ids.Org](), time.Now()
	inst := pap.Instance{Org: org, Agent: ids.NewV7(), Instance: ids.NewV7()}

	wtSigner, err := reg.Signer(keys.PurposeWorkloadTokens)
	if err != nil {
		t.Fatal(err)
	}
	wt, _, err := pap.Issue(wtSigner, bearerIssuer, pap.Token{
		Instance: inst, Environment: ids.NewV7(), JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Level: 1,
	}, now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	mint := func(keyPurpose keys.Purpose, o ids.OrgID, resource string, at time.Time) string {
		t.Helper()
		m := &mcptoken.Minter{Keys: mcptoken.SignerFunc(func() (*jws.Signer, error) { return reg.Signer(keyPurpose) }), Issuer: bearerIssuer}
		tok, _, err := m.Mint(context.Background(), ports.AccessClaims{
			Org: o, Environment: ids.NewV7(), Agent: inst.Agent, Instance: inst.Instance, Run: ids.NewV7(), Connection: "github",
			Resource: resource, ClientKind: ports.ClientMcp, Client: ids.NewV7(), Scope: []string{"tickets.read"},
		}, at)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	mcp := mint(keys.PurposeMcpTokens, org, oauthURL, now)

	for _, tc := range []struct {
		name, token, url, proof string
		code                    pap.Code
	}{
		{"a workload token with no proof", wt, papURL, "", pap.CodeInvalidProof},
		{"a workload token on the OAuth route", wt, oauthURL, "", pap.CodeInvalidToken},
		{"a workload token with a proof on the OAuth route", wt, oauthURL, "eyJ.x.y", pap.CodeInvalidToken},
		{"an MCP token on a PAP/1 route", mcp, papURL, "", pap.CodeInvalidToken},
		{"an MCP token with a proof", mcp, oauthURL, "eyJ.x.y", pap.CodeInvalidToken},
		{"an MCP token for another server", mint(keys.PurposeMcpTokens, org, "https://gw.example.test/mcp-oauth/slack", now), oauthURL, "", pap.CodeInvalidToken},
		{"an expired MCP token", mint(keys.PurposeMcpTokens, org, oauthURL, now.Add(-10*time.Minute)), oauthURL, "", pap.CodeTokenExpired},
		{"an MCP token of another org", mint(keys.PurposeMcpTokens, ids.New[ids.Org](), oauthURL, now), oauthURL, "", pap.CodeInvalidToken},
		{"an MCP token signed with a workload-token key", mint(keys.PurposeWorkloadTokens, org, oauthURL, now), oauthURL, "", pap.CodeInvalidToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Identify(context.Background(), org, app.IdentifyInput{
				Request: pap.Request{Method: "POST", URL: tc.url, BodySHA256: sha256.Sum256(nil), Token: tc.token}, Proof: tc.proof,
			})
			var pe *pap.Error
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want a PAP error", err)
			}
			if pe.Code != tc.code {
				t.Fatalf("code %s, want %s", pe.Code, tc.code)
			}
		})
	}
	if !app.OAuthRoute(oauthURL) || app.OAuthRoute(papURL) {
		t.Fatal("OAuthRoute")
	}
}
