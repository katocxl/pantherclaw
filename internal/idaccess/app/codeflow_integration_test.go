// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/idaccess/app"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	mcpClient   = "https://editor.example/oauth/client.json"
	mcpRedirect = "http://127.0.0.1:4567/callback"
	verifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-and-some-more-chars"
)

type docs map[string]ports.ClientMetadata

func (d docs) Fetch(_ context.Context, u string) (ports.ClientMetadata, error) {
	md, ok := d[u]
	if !ok {
		return ports.ClientMetadata{}, errors.New("unreachable")
	}
	return md, nil
}

func challenge(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// codeEnv adds an allow-listed MCP client of the agent to env.
func codeEnv(t *testing.T) (*env, *app.CodeFlow, ids.UUID) {
	t.Helper()
	e := newEnv(t)
	inst, client := ids.NewV7(), ids.NewV7()
	e.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'mcp_client')`, e.org, inst, e.agent, "unheld-"+inst.String())
	e.exec(t, `INSERT INTO pc.mcp_clients (org_id, id, client_url, agent_id, instance_id, state, created_by, activated_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6, now())`, e.org, client, mcpClient, e.agent, inst, e.user)
	flow := &app.CodeFlow{
		Pool: e.pool, Runs: e.ex.Runs, Tokens: e.ex.Tokens, PublicURL: publicURL, Clock: clock.System{},
		Documents: docs{mcpClient: {ClientID: mcpClient, Name: "Editor", RedirectURIs: []string{mcpRedirect}}},
	}
	return e, flow, client
}

func authorizeQuery(edit func(url.Values)) url.Values {
	q := url.Values{
		"response_type": {"code"}, "client_id": {mcpClient}, "redirect_uri": {mcpRedirect}, "state": {"st-1"},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "resource": {resource},
	}
	if edit != nil {
		edit(q)
	}
	return q
}

func codeOf(t *testing.T, redirect string) string {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil || !strings.HasPrefix(redirect, mcpRedirect+"?") {
		t.Fatalf("redirect %q", redirect)
	}
	return u.Query().Get("code")
}

func redeem(flow *app.CodeFlow, code, v string) (authnapp.TokenResponse, error) {
	return flow.AuthorizationCode(context.Background(), url.Values{
		"grant_type": {app.GrantAuthorizationCode}, "code": {code}, "client_id": {mcpClient}, "redirect_uri": {mcpRedirect},
		"code_verifier": {v}, "resource": {resource},
	})
}

func refresh(flow *app.CodeFlow, token string) (authnapp.TokenResponse, error) {
	return flow.Refresh(context.Background(), url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {mcpClient}})
}

// TestHR628_TheCodeFlowChecksClientRedirectAndPKCE (G0 M26 D408.4,
// HR-628): only an allow-listed client with an exact redirect URI from its
// document is shown to the person; PKCE S256 and the resource are
// required; the approval redirects with code, state and iss; a code is
// spent by its first use, right or wrong; the run is the signed-in
// person's own over their existing grant, and no grant is written.
// Covers: F913
func TestHR628_TheCodeFlowChecksClientRedirectAndPKCE(t *testing.T) {
	e, flow, _ := codeEnv(t)
	ctx := context.Background()
	c, err := flow.Prepare(ctx, e.org, authorizeQuery(nil))
	if err != nil || c.Agent != e.agent || c.Connection != "github" || c.ClientHost != "editor.example" || c.ClientName != "Editor" {
		t.Fatalf("consent %+v %v", c, err)
	}
	for name, tc := range map[string]struct {
		edit     func(url.Values)
		redirect bool
		code     string
	}{
		"an unlisted client":         {func(q url.Values) { q.Set("client_id", "https://other.example/c.json") }, false, "invalid_request"},
		"an unregistered redirect":   {func(q url.Values) { q.Set("redirect_uri", "http://127.0.0.1:9/cb") }, false, "invalid_request"},
		"plain PKCE":                 {func(q url.Values) { q.Set("code_challenge_method", "plain") }, true, "invalid_request"},
		"no PKCE":                    {func(q url.Values) { q.Del("code_challenge") }, true, "invalid_request"},
		"no resource":                {func(q url.Values) { q.Del("resource") }, true, "invalid_target"},
		"another gateway's resource": {func(q url.Values) { q.Set("resource", "https://evil.example/mcp-oauth/github") }, true, "invalid_target"},
		"an implicit flow":           {func(q url.Values) { q.Set("response_type", "token") }, true, "unsupported_response_type"},
		"a repeated parameter":       {func(q url.Values) { q.Add("state", "two") }, false, "invalid_request"},
	} {
		_, err := flow.Prepare(ctx, e.org, authorizeQuery(tc.edit))
		var ae *app.AuthorizeError
		if !errors.As(err, &ae) || ae.Redirect != tc.redirect || ae.Code != tc.code {
			t.Errorf("%s: %v", name, err)
		}
	}

	before := e.count(t, "SELECT count(*) FROM pc.grants")
	redirect, err := flow.Approve(ctx, e.org, e.user, authorizeQuery(nil))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	if u.Query().Get("state") != "st-1" || u.Query().Get("iss") != publicURL+"/orgs/"+e.org.String() {
		t.Fatalf("redirect %s", redirect)
	}
	code := codeOf(t, redirect)
	if _, err := redeem(flow, code, verifier+"x"); oauthCode(err) != "invalid_grant "+authnapp.ErrInvalidGrant.Description {
		t.Fatalf("a wrong verifier: %s", oauthCode(err))
	}
	if _, err := redeem(flow, code, verifier); err == nil {
		t.Fatal("a spent code redeemed")
	}

	res, err := redeem(flow, codeOf(t, mustApprove(t, flow, e)), verifier)
	if err != nil || res.RefreshToken == "" || res.RunID == "" || res.ExpiresIn > 300 {
		t.Fatalf("redeem: %+v %v", res, err)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.runs WHERE id = $1 AND principal_source = 'launcher' AND launcher_user_id = $2
		AND principal_user_id = $2 AND launcher_instance_id IS NULL AND grant_id IS NOT NULL`, res.RunID, e.user); n != 1 {
		t.Fatal("the run is not the person's own over their grant")
	}
	if e.count(t, "SELECT count(*) FROM pc.grants") != before {
		t.Fatal("a grant was written")
	}
	if e.count(t, "SELECT count(*) FROM pc.mcp_authorization_codes WHERE used_at IS NULL") != 0 {
		t.Fatal("an unspent code is left")
	}
}

func mustApprove(t *testing.T, flow *app.CodeFlow, e *env) string {
	t.Helper()
	r, err := flow.Approve(context.Background(), e.org, e.user, authorizeQuery(nil))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestHR628_RefreshTokensRotateAndReuseKillsTheFamily (D408.4, HR-628):
// a refresh token is rotated on use; presenting a rotated one is refused,
// kills the family and is audited; a removed client or an ended run stops
// refreshing.
// Covers: F913
func TestHR628_RefreshTokensRotateAndReuseKillsTheFamily(t *testing.T) {
	e, flow, client := codeEnv(t)
	first, err := redeem(flow, codeOf(t, mustApprove(t, flow, e)), verifier)
	if err != nil {
		t.Fatal(err)
	}
	second, err := refresh(flow, first.RefreshToken)
	if err != nil || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken || second.RunID != first.RunID {
		t.Fatalf("rotation: %+v %v", second, err)
	}
	if _, err := refresh(flow, first.RefreshToken); oauthCode(err) == "ok" {
		t.Fatal("a rotated refresh token was accepted")
	}
	if _, err := refresh(flow, second.RefreshToken); oauthCode(err) == "ok" {
		t.Fatal("the family survived a reuse")
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.idaccess.refresh_reuse'", e.org); n != 1 {
		t.Fatalf("reuse audit events: %d", n)
	}

	// A new family; the run ending stops it, as does removing the client.
	third, err := redeem(flow, codeOf(t, mustApprove(t, flow, e)), verifier)
	if err != nil {
		t.Fatal(err)
	}
	e.exec(t, "UPDATE pc.runs SET state = 'ENDED', ended_at = now(), end_reason = 'test' WHERE id = $1", third.RunID)
	if _, err := refresh(flow, third.RefreshToken); oauthCode(err) == "ok" {
		t.Fatal("a refresh token outlived its run")
	}
	fourth, err := redeem(flow, codeOf(t, mustApprove(t, flow, e)), verifier)
	if err != nil {
		t.Fatal(err)
	}
	e.exec(t, "UPDATE pc.mcp_clients SET state = 'REMOVED', removed_by = $2, removed_at = now() WHERE id = $1", client, e.user)
	if _, err := refresh(flow, fourth.RefreshToken); oauthCode(err) == "ok" {
		t.Fatal("a removed client refreshed")
	}
	if _, err := flow.Prepare(context.Background(), e.org, authorizeQuery(nil)); err == nil {
		t.Fatal("a removed client was shown for consent")
	}
}
