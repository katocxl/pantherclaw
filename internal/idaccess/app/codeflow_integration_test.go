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
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idaccess/app"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
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
	doc := ports.ClientMetadata{ClientID: mcpClient, Name: "Editor", RedirectURIs: []string{mcpRedirect}}
	e.exec(t, `INSERT INTO pc.mcp_clients (org_id, id, client_url, agent_id, instance_id, state, created_by, activated_at, client_name,
		redirect_uris, document_digest) VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6, now(), $7, $8, $9)`,
		e.org, client, mcpClient, e.agent, inst, e.user, doc.Name, doc.RedirectURIs, app.DocumentDigest(doc))
	flow := &app.CodeFlow{
		Pool: e.pool, Runs: e.ex.Runs, Tokens: e.ex.Tokens, PublicURL: publicURL, Clock: clock.System{},
		Documents: docs{mcpClient: doc},
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
	if err != nil || c.Agent != e.agent || c.Connection != "github" || c.ClientHost != "editor.example" || c.ClientName != "Editor" ||
		!c.LoopbackRedirect {
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
	// The run behind the family ended with it, so its access tokens stop at once.
	if n := e.count(t, "SELECT count(*) FROM pc.runs WHERE id = $1 AND state = 'REVOKED' AND end_reason = 'refresh_token_reused'", first.RunID); n != 1 {
		t.Fatal("the run outlived its killed refresh family")
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

// TestHR628_ASpentCodeUsedAgainEndsItsRun (RFC 6749 §4.1.2, T-269): a code
// presented after it was redeemed is refused and ends the run it started,
// so every token issued from it stops at once.
// Covers: F913
func TestHR628_ASpentCodeUsedAgainEndsItsRun(t *testing.T) {
	e, flow, _ := codeEnv(t)
	code := codeOf(t, mustApprove(t, flow, e))
	res, err := redeem(flow, code, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redeem(flow, code, verifier); oauthCode(err) == "ok" {
		t.Fatal("a spent code redeemed twice")
	}
	if n := e.count(t, "SELECT count(*) FROM pc.runs WHERE id = $1 AND state = 'REVOKED' AND end_reason = 'authorization_code_reused'",
		res.RunID); n != 1 {
		t.Fatal("the run outlived a second use of its code")
	}
	if _, err := refresh(flow, res.RefreshToken); oauthCode(err) == "ok" {
		t.Fatal("a refresh token outlived its reused code")
	}
}

// TestHR628_TheTokenEndpointChecksTheCodesRequest (HR-628): an expired
// code, a redirect_uri or client_id other than the authorization request's,
// or a client removed since the consent gets no token, and each spends the
// code.
// Covers: F913
func TestHR628_TheTokenEndpointChecksTheCodesRequest(t *testing.T) {
	e, flow, client := codeEnv(t)
	form := func(code string, edit func(url.Values)) url.Values {
		f := url.Values{
			"grant_type": {app.GrantAuthorizationCode}, "code": {code}, "client_id": {mcpClient}, "redirect_uri": {mcpRedirect},
			"code_verifier": {verifier}, "resource": {resource},
		}
		edit(f)
		return f
	}
	for name, edit := range map[string]func(url.Values){
		"a redirect_uri mismatch": func(f url.Values) { f.Set("redirect_uri", "http://127.0.0.1:4567/other") },
		"a client_id mismatch":    func(f url.Values) { f.Set("client_id", "https://other.example/c.json") },
	} {
		code := codeOf(t, mustApprove(t, flow, e))
		if _, err := flow.AuthorizationCode(context.Background(), form(code, edit)); !strings.HasPrefix(oauthCode(err), "invalid_grant") {
			t.Errorf("%s: %s", name, oauthCode(err))
		}
		if _, err := redeem(flow, code, verifier); oauthCode(err) == "ok" {
			t.Errorf("%s: the code was not spent", name)
		}
	}

	expired := codeOf(t, mustApprove(t, flow, e))
	sum := sha256.Sum256([]byte(expired))
	e.db.AdminDo(t, func(c *pgx.Conn) error {
		_, err := c.Exec(context.Background(), `UPDATE pc.mcp_authorization_codes
			SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute' WHERE code_hash = $1`, sum[:])
		return err
	})
	if _, err := redeem(flow, expired, verifier); !strings.HasPrefix(oauthCode(err), "invalid_grant") {
		t.Errorf("an expired code: %s", oauthCode(err))
	}

	removed := codeOf(t, mustApprove(t, flow, e))
	e.exec(t, "UPDATE pc.mcp_clients SET state = 'REMOVED', removed_by = $2, removed_at = now() WHERE id = $1", client, e.user)
	if _, err := redeem(flow, removed, verifier); !strings.HasPrefix(oauthCode(err), "invalid_grant") {
		t.Errorf("a removed client: %s", oauthCode(err))
	}
	if n := e.count(t, "SELECT count(*) FROM pc.runs"); n != 0 {
		t.Fatalf("%d runs started", n)
	}
}

// TestHR625_AnEditedDocumentGetsNoCodeAtANewRedirect (HR-625, HR-628): a
// redirect URI is usable only while both the confirmed document and the
// live one list it. A document edited on its host to add a URI gets no
// code there: the request is refused CLIENT_DOCUMENT_CHANGED on the page,
// audited and told to the admins. The consent page shows the confirmed
// name, not the live one.
// Covers: F913
func TestHR625_AnEditedDocumentGetsNoCodeAtANewRedirect(t *testing.T) {
	e, flow, _ := codeEnv(t)
	ctx := context.Background()
	notes := &adminNotes{t: t}
	e.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, 'org_admin', $3, 'ORG', 'test')`,
		e.org, ids.NewV7(), e.user)
	flow.Notify = notes
	d := flow.Documents.(docs)
	const added = "http://127.0.0.1:9999/steal"
	d[mcpClient] = ports.ClientMetadata{ClientID: mcpClient, Name: "Totally Trusted", RedirectURIs: []string{mcpRedirect, added}}

	at := func(redirect string) url.Values {
		return authorizeQuery(func(q url.Values) { q.Set("redirect_uri", redirect) })
	}
	for _, call := range []func() error{
		func() error { _, err := flow.Prepare(ctx, e.org, at(added)); return err },
		func() error { _, err := flow.Approve(ctx, e.org, e.user, at(added)); return err },
	} {
		var ae *app.AuthorizeError
		if err := call(); !errors.As(err, &ae) || ae.Code != "CLIENT_DOCUMENT_CHANGED" || ae.Redirect {
			t.Fatalf("a redirect the live document added: %v", err)
		}
	}
	if n := e.count(t, "SELECT count(*) FROM pc.mcp_authorization_codes"); n != 0 {
		t.Fatalf("%d codes issued", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.idaccess.client_document_changed'",
		e.org); n != 2 {
		t.Fatalf("document change audit events: %d", n)
	}
	if m := notes.last(); m.Type != "idaccess.client_document_changed" || m.Org != e.org || !slices.Contains(m.Personal, e.user) {
		t.Fatalf("admins not told: %+v", m)
	}

	// The confirmed redirect still works, under the confirmed name.
	c, err := flow.Prepare(ctx, e.org, authorizeQuery(nil))
	if err != nil || c.ClientName != "Editor" {
		t.Fatalf("the confirmed redirect: %+v %v", c, err)
	}
	// A confirmed redirect the live document dropped is refused too.
	d[mcpClient] = ports.ClientMetadata{ClientID: mcpClient, Name: "Editor", RedirectURIs: []string{added}}
	if _, err := flow.Prepare(ctx, e.org, authorizeQuery(nil)); err == nil {
		t.Fatal("a redirect the live document no longer lists was used")
	}
}

// outboxNotes enqueues into the notification outbox itself, so its dedupe
// key is the real one.
type outboxNotes struct{}

func (outboxNotes) Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	r, err := ndomain.Render(m.Type, m.Params)
	if err != nil {
		return napp.Enqueued{}, err
	}
	np := dbq.InsertNotificationParams{
		OrgID: m.Org, ID: ids.NewV7(), Type: r.Type, Severity: string(r.Severity), Title: r.Title, Body: r.Body,
		LinkPath: r.Link, TtlSeconds: 3600,
	}
	if m.DedupeKey != "" {
		np.DedupeKey = &m.DedupeKey
	}
	n, err := dbq.New(tx).InsertNotification(ctx, np)
	return napp.Enqueued{Notification: np.ID, Duplicate: n == 0}, err
}

// TestHR625_AChangedDocumentNotifiesOncePerDocument (D560): every refused
// attempt at a redirect a changed document added is audited, but the admins
// are told once per client and live document; a further change tells them
// again.
// Covers: F913
func TestHR625_AChangedDocumentNotifiesOncePerDocument(t *testing.T) {
	e, flow, _ := codeEnv(t)
	ctx := context.Background()
	flow.Notify = outboxNotes{}
	d := flow.Documents.(docs)
	const added = "http://127.0.0.1:9999/steal"
	at := authorizeQuery(func(q url.Values) { q.Set("redirect_uri", added) })
	refuse := func() {
		t.Helper()
		var ae *app.AuthorizeError
		if _, err := flow.Prepare(ctx, e.org, at); !errors.As(err, &ae) || ae.Code != "CLIENT_DOCUMENT_CHANGED" {
			t.Fatalf("a redirect a changed document added: %v", err)
		}
	}
	counts := func() (audits, notices int) {
		return e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.idaccess.client_document_changed'", e.org),
			e.count(t, "SELECT count(*) FROM pc.notifications WHERE type = 'idaccess.client_document_changed'")
	}

	d[mcpClient] = ports.ClientMetadata{ClientID: mcpClient, Name: "Editor", RedirectURIs: []string{mcpRedirect, added}}
	refuse()
	refuse()
	if a, n := counts(); a != 2 || n != 1 {
		t.Fatalf("two attempts at one changed document: %d audit entries, %d notices (want 2, 1)", a, n)
	}
	d[mcpClient] = ports.ClientMetadata{ClientID: mcpClient, Name: "Editor", RedirectURIs: []string{mcpRedirect, added, "http://127.0.0.1:9998/x"}}
	refuse()
	if a, n := counts(); a != 3 || n != 2 {
		t.Fatalf("a further change: %d audit entries, %d notices (want 3, 2)", a, n)
	}
}

// TestHR628_ASecondUseDuringTheRedemptionEndsItsRun (D559): a code spent,
// then presented again before its redemption finished, gives no token:
// the second use marks it reused, and the redemption ends the run it
// started, audited, and issues nothing.
// Covers: F913
func TestHR628_ASecondUseDuringTheRedemptionEndsItsRun(t *testing.T) {
	e, flow, _ := codeEnv(t)
	ctx := context.Background()
	code := codeOf(t, mustApprove(t, flow, e))
	row, err := flow.SpendCode(ctx, e.org, code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redeem(flow, code, verifier); !strings.HasPrefix(oauthCode(err), "invalid_grant") {
		t.Fatalf("the second use: %s", oauthCode(err))
	}
	form := url.Values{
		"grant_type": {app.GrantAuthorizationCode}, "code": {code}, "client_id": {mcpClient}, "redirect_uri": {mcpRedirect},
		"code_verifier": {verifier}, "resource": {resource},
	}
	res, err := flow.FinishCode(ctx, e.org, row, form)
	if !strings.HasPrefix(oauthCode(err), "invalid_grant") || res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("the redemption after a second use: %+v %s", res, oauthCode(err))
	}
	if n := e.count(t, "SELECT count(*) FROM pc.runs WHERE state = 'REVOKED' AND end_reason = 'authorization_code_reused'"); n != 1 {
		t.Fatalf("ended runs: %d", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.runs WHERE state = 'ACTIVE'"); n != 0 {
		t.Fatalf("active runs: %d", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.mcp_refresh_tokens"); n != 0 {
		t.Fatalf("refresh tokens issued: %d", n)
	}
	for kind, want := range map[string]int{"audit.idaccess.code_reuse": 1, "audit.run.ended": 1, "audit.idaccess.token_issued": 0} {
		if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", e.org, kind); n != want {
			t.Errorf("%s: %d, want %d", kind, n, want)
		}
	}
}
