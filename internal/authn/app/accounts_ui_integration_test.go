// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/accounts"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// withAccounts enables sign-in without an org on the browser env.
func (b *browserEnv) withAccounts(t *testing.T, selfServe bool) *accounts.Store {
	t.Helper()
	lic := entitlements.LicenceFunc(func(context.Context) (billing.Entitlements, error) { return billing.CommunityEntitlements(), nil })
	ents, err := entitlements.New(b.pool, lic, entitlements.ModeOff, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := accounts.NewStore(b.pool)
	b.browser.WithAccounts(store, accounts.NewInvitations(store, ents), selfServe)
	return store
}

// signInWithoutOrg runs a sign-in without an org (optionally carrying an
// invitation).
func (b *browserEnv) signInWithoutOrg(t *testing.T, invitation string) authnapp.BrowserSignIn {
	t.Helper()
	red, err := b.browser.Start(context.Background(), authnapp.BrowserStart{Invitation: invitation, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := b.browser.Callback(context.Background(), "test", b.authorize(t, red.URL), red.Binding,
		authnapp.ClientMeta{UserAgent: "test-agent", IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHR353_SwitchingOrgIsAFreshSignIn: a sign-in without an org that
// finds several orgs opens an account session that may pick one org once,
// only right after the sign-in; another org needs another sign-in.
func TestHR353_SwitchingOrgIsAFreshSignIn(t *testing.T) {
	b := newBrowserEnv(t)
	b.withAccounts(t, false)
	second := ids.New[ids.Org]()
	b.exec(t, second, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'second')", second)
	b.exec(t, second, `INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, $3, 'alice', 'alice@example.test')`,
		second, ids.NewV7(), b.idp.Issuer())
	ctx := context.Background()
	out := b.signInWithoutOrg(t, "")
	if out.Reason != "" || out.Kind != authnapp.SessionAccount || out.Next != authnapp.OrgPickerPath || out.Return != authnapp.AccountPath {
		t.Fatalf("sign-in = %+v", out)
	}
	// D88: the page a sign-in asked for is kept for the picker.
	red, err := b.browser.Start(ctx, authnapp.BrowserStart{Next: "/app/agents", ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	withNext, err := b.browser.Callback(ctx, "test", b.authorize(t, red.URL), red.Binding, authnapp.ClientMeta{IP: "192.0.2.1"})
	if err != nil || withNext.Next != authnapp.OrgPickerPath || withNext.Return != "/app/agents" {
		t.Fatalf("sign-in with a return path = %+v, %v", withNext, err)
	}
	s, err := b.browser.AuthenticateAccount(ctx, out.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if ms, err := b.browser.Memberships(ctx, s); err != nil || len(ms) != 2 {
		t.Fatalf("memberships = %v, %v", ms, err)
	}
	if _, err := b.browser.PickOrg(ctx, s, ids.New[ids.Org](), authnapp.ClientMeta{}); !errors.Is(err, authnapp.ErrNotPickable) {
		t.Errorf("an org the account is not in: %v", err)
	}
	picked, err := b.browser.PickOrg(ctx, s, second, authnapp.ClientMeta{})
	if err != nil || picked.Org != second || picked.Secret == "" {
		t.Fatalf("pick = %+v, %v", picked, err)
	}
	if _, err := b.browser.Authenticate(ctx, picked.Secret); err != nil {
		t.Errorf("the picked org's session: %v", err)
	}
	// The account session ended with the pick: no second org from it.
	if _, err := b.browser.AuthenticateAccount(ctx, out.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("account session after the pick: %v", err)
	}
	// A later pick from an old account session is refused.
	out = b.signInWithoutOrg(t, "")
	s, err = b.browser.AuthenticateAccount(ctx, out.Secret)
	if err != nil {
		t.Fatal(err)
	}
	// D88: the window is 15 minutes; 11 minutes in, the session still
	// picks (an org it is not in stays not pickable, not stale).
	b.d.AdminExec(t, "UPDATE pc.account_sessions SET created_at = now() - interval '11 minutes', expires_at = expires_at - interval '11 minutes', last_seen_at = now() WHERE id = $1", s.Session)
	s, err = b.browser.AuthenticateAccount(ctx, out.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if !authnapp.PickerFresh(s) {
		t.Errorf("an 11-minute-old account session is past the picker window")
	}
	if _, err := b.browser.PickOrg(ctx, s, ids.New[ids.Org](), authnapp.ClientMeta{}); !errors.Is(err, authnapp.ErrNotPickable) {
		t.Errorf("an 11-minute-old account session, foreign org: %v", err)
	}
	b.d.AdminExec(t, "UPDATE pc.account_sessions SET created_at = now() - interval '16 minutes', expires_at = expires_at - interval '5 minutes', last_seen_at = now() WHERE id = $1", s.Session)
	s, err = b.browser.AuthenticateAccount(ctx, out.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.browser.PickOrg(ctx, s, b.org, authnapp.ClientMeta{}); !errors.Is(err, authnapp.ErrPickerStale) {
		t.Errorf("a stale account session picked an org: %v", err)
	}
	// The pending sign-in kept only hashes of what it compares.
	var plain int
	b.d.AdminQueryRow(t, `SELECT count(*)::int FROM information_schema.columns WHERE table_schema = 'pc'
		AND table_name = 'account_login_requests' AND column_name IN ('nonce', 'state_token')`, nil, &plain)
	if plain != 0 {
		t.Error("account sign-ins store a plaintext nonce or state")
	}
}

// TestHR350_ASignInWithoutAnOrgOpensAnOrgOrAnAccountSession: one
// membership opens that org; none is NOT_A_MEMBER unless self-serve is
// on, which opens an account session (no org, no roles).
func TestHR350_ASignInWithoutAnOrgOpensAnOrgOrAnAccountSession(t *testing.T) {
	b := newBrowserEnv(t)
	store := b.withAccounts(t, false)
	ctx := context.Background()
	out := b.signInWithoutOrg(t, "")
	if out.Reason != "" || out.Kind != authnapp.SessionOrg || out.Org != b.org {
		t.Fatalf("one membership: %+v", out)
	}
	if n := b.count(t, "SELECT count(*)::int FROM pc.users WHERE org_id = $1 AND account_id = $2", b.org, out.Account); n != 1 {
		t.Error("the user was not linked to its account")
	}
	if _, err := store.Get(ctx, out.Account); err != nil {
		t.Errorf("account: %v", err)
	}
	b.idp.SignIn(oidctest.User{Subject: "newcomer", Email: "new@example.test", EmailVerified: true})
	if out := b.signInWithoutOrg(t, ""); out.Reason != "NOT_A_MEMBER" {
		t.Errorf("no org, self-serve off: %+v", out)
	}
	b.withAccounts(t, true)
	out = b.signInWithoutOrg(t, "")
	// D94: nothing to pick, so the console's create-org page, not the picker.
	if out.Reason != "" || out.Kind != authnapp.SessionAccount || out.Next != authnapp.WelcomePath {
		t.Fatalf("no org, self-serve on: %+v", out)
	}
	// A console page the sign-in asked for is kept; anything else lands on
	// the create-org page.
	for next, want := range map[string]string{
		"/app/settings/billing": "/app/settings/billing",
		authnapp.ConsolePath:    authnapp.WelcomePath,
		"/approvals":            authnapp.WelcomePath,
	} {
		red, err := b.browser.Start(ctx, authnapp.BrowserStart{Next: next, ClientIP: "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := b.browser.Callback(ctx, "test", b.authorize(t, red.URL), red.Binding, authnapp.ClientMeta{IP: "192.0.2.1"})
		if err != nil || got.Kind != authnapp.SessionAccount || got.Next != want {
			t.Errorf("no org, next %q: %+v, %v", next, got, err)
		}
	}
	s, err := b.browser.AuthenticateAccount(ctx, out.Secret)
	if err != nil || s.Account != out.Account {
		t.Fatalf("account session: %+v, %v", s, err)
	}
	// An account session is not an org session.
	if _, err := b.browser.Authenticate(ctx, out.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("an account cookie authenticated as an org session: %v", err)
	}
	if err := b.browser.EndAccountSession(ctx, s, "LOGOUT"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.browser.AuthenticateAccount(ctx, out.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("after sign-out: %v", err)
	}
}

// TestHR352_AnInvitationLinkSignsInAndJoinsOnlyTheInvitedEmail.
func TestHR352_AnInvitationLinkSignsInAndJoinsOnlyTheInvitedEmail(t *testing.T) {
	b := newBrowserEnv(t)
	b.withAccounts(t, false)
	invite := func(email string) string {
		tok, err := credential.New(credential.Invitation, "", b.org)
		if err != nil {
			t.Fatal(err)
		}
		b.exec(t, b.org, `INSERT INTO pc.invitations (org_id, id, email, roles, token_hash, created_by, expires_at)
			VALUES ($1, $2, $3, '{viewer}', $4, 'test', now() + interval '1 day')`, b.org, ids.NewV7(), email, tok.Hash())
		return tok.Reveal()
	}
	b.idp.SignIn(oidctest.User{Subject: "bob", Email: "bob@example.test", EmailVerified: true})
	if out := b.signInWithoutOrg(t, invite("carol@example.test")); out.Reason != "INVITATION_EMAIL_MISMATCH" {
		t.Errorf("another email: %+v", out)
	}
	out := b.signInWithoutOrg(t, invite("bob@example.test"))
	if out.Reason != "" || out.Org != b.org || out.Secret == "" {
		t.Fatalf("invitation sign-in: %+v", out)
	}
	if _, err := b.browser.Authenticate(context.Background(), out.Secret); err != nil {
		t.Errorf("the joined org's session: %v", err)
	}
	if _, err := b.browser.Start(context.Background(), authnapp.BrowserStart{Invitation: "pci_garbage"}); !errors.Is(err, authnapp.ErrSignInUnavailable) {
		t.Errorf("a malformed invitation link: %v", err)
	}
}
