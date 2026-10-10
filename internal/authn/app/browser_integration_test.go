// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const browserIssuer = "https://pc.example.test"

type browserEnv struct {
	*env
	idp     *oidctest.Provider
	browser *authnapp.Browser
	device  *authnapp.Device
	org     ids.OrgID
	user    ids.UUID
}

// newBrowserEnv is one org with one enabled org admin, alice, known to the
// in-process provider.
func newBrowserEnv(t *testing.T) *browserEnv {
	t.Helper()
	e := newEnv(t)
	idp := oidctest.New(t)
	prov, err := oidcrp.New(oidcrp.Config{
		Name: "test", Issuer: idp.Issuer(), ClientID: idp.ClientID, ClientSecret: pclog.NewSecret([]byte(idp.ClientSecret)),
		AllowInsecureLoopback: true, HTTPClient: idp.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b := &browserEnv{
		env: e, idp: idp, org: ids.New[ids.Org](), user: ids.NewV7(),
		browser: authnapp.NewBrowser(e.pool, browserIssuer, []authnapp.IdP{prov}, clock.System{}, nil),
		device:  authnapp.NewDevice(e.pool, e.tokens, browserIssuer, []authnapp.IdP{prov}, clock.System{}, nil),
	}
	e.exec(t, b.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'browser')", b.org)
	e.exec(t, b.org, `INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, $3, 'alice', 'alice@example.test')`,
		b.org, b.user, idp.Issuer())
	e.exec(t, b.org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, 'org_admin', $3, 'ORG', 'test')`, b.org, ids.NewV7(), b.user)
	idp.SignIn(oidctest.User{Subject: "alice", Email: "alice@example.test", EmailVerified: true, Name: "Alice"})
	return b
}

// authorize follows the provider's authorization endpoint once and returns
// the callback's query parameters.
func (b *browserEnv) authorize(t *testing.T, providerURL string) url.Values {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, providerURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	return loc.Query()
}

// signIn runs a full browser sign-in and returns the result.
func (b *browserEnv) signIn(t *testing.T, recent bool) authnapp.BrowserSignIn {
	t.Helper()
	red, err := b.browser.Start(context.Background(), authnapp.BrowserStart{Org: b.org.String(), Recent: recent})
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

func (b *browserEnv) mustSignIn(t *testing.T) authnapp.BrowserSignIn {
	t.Helper()
	out := b.signIn(t, false)
	if out.Reason != "" || out.Secret == "" {
		t.Fatalf("sign-in refused: %q", out.Reason)
	}
	return out
}

func (b *browserEnv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	err := b.pool.InTenantTx(context.Background(), b.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (b *browserEnv) endReason(t *testing.T, id ids.UUID) string {
	t.Helper()
	var r *string
	err := b.pool.InTenantTx(context.Background(), b.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT end_reason FROM pc.sessions WHERE id = $1", id).Scan(&r)
	})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		return ""
	}
	return *r
}

func TestHR152_BrowserCallbackIsBoundToItsBrowserAndState(t *testing.T) {
	b := newBrowserEnv(t)
	ctx := context.Background()
	start := func() authnapp.Redirect {
		t.Helper()
		red, err := b.browser.Start(ctx, authnapp.BrowserStart{Org: b.org.String()})
		if err != nil {
			t.Fatal(err)
		}
		return red
	}
	refused := func(name string, params url.Values, binding, want string) {
		t.Helper()
		out, err := b.browser.Callback(ctx, "test", params, binding, authnapp.ClientMeta{})
		if err != nil || out.Reason != want || out.Secret != "" {
			t.Errorf("%s: reason %q secret set=%v err %v, want %q", name, out.Reason, out.Secret != "", err, want)
		}
	}

	red := start()
	refused("no binding cookie (login CSRF)", b.authorize(t, red.URL), "", "LOGIN_FAILED")
	other := start()
	refused("another browser's binding", b.authorize(t, other.URL), red.Binding, "LOGIN_FAILED")

	red = start()
	params := b.authorize(t, red.URL)
	if out, err := b.browser.Callback(ctx, "test", params, red.Binding, authnapp.ClientMeta{}); err != nil || out.Secret == "" {
		t.Fatalf("valid sign-in: %+v %v", out, err)
	}
	if _, err := b.browser.Callback(ctx, "test", params, red.Binding, authnapp.ClientMeta{}); !errors.Is(err, authnapp.ErrBadCallback) {
		t.Errorf("reused state: %v, want ErrBadCallback", err)
	}

	b.idp.Set(oidctest.Knobs{WrongIssParam: "https://other-idp.example"})
	red = start()
	refused("another provider's iss (mix-up)", b.authorize(t, red.URL), red.Binding, "LOGIN_FAILED")
	b.idp.Set(oidctest.Knobs{Nonce: "forged"})
	red = start()
	refused("wrong nonce", b.authorize(t, red.URL), red.Binding, "LOGIN_FAILED")
	b.idp.Set(oidctest.Knobs{Error: "access_denied"})
	red = start()
	refused("provider error", b.authorize(t, red.URL), red.Binding, "IDP_ERROR")
	b.idp.Set(oidctest.Knobs{})

	red = start()
	params = b.authorize(t, red.URL)
	b.d.AdminExec(t, "UPDATE pc.login_requests SET expires_at = now() - interval '1 second' WHERE org_id = $1 AND state = 'PENDING'", b.org)
	if _, err := b.browser.Callback(ctx, "test", params, red.Binding, authnapp.ClientMeta{}); !errors.Is(err, authnapp.ErrBadCallback) {
		t.Errorf("expired state: %v, want ErrBadCallback", err)
	}

	// The flows share the callback URL but never each other's states.
	red = start()
	params = b.authorize(t, red.URL)
	if !authnapp.IsBrowserState(params) {
		t.Fatal("a browser state is not recognized as one")
	}
	if _, err := b.device.Callback(ctx, "test", params, red.Binding); !errors.Is(err, authnapp.ErrBadCallback) {
		t.Errorf("browser state on the device path: %v, want ErrBadCallback", err)
	}
	devState, err := credential.New(credential.OAuthState, "", b.org)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.browser.Callback(ctx, "test", url.Values{"state": {devState.Reveal()}}, red.Binding, authnapp.ClientMeta{}); !errors.Is(err, authnapp.ErrBadCallback) {
		t.Errorf("device state on the browser path: %v, want ErrBadCallback", err)
	}
}

func TestHR152_RecentSignInNeedsAFreshAuthTime(t *testing.T) {
	b := newBrowserEnv(t)
	if out := b.signIn(t, true); out.Reason != "" {
		t.Fatalf("fresh auth_time refused: %q", out.Reason)
	}
	b.idp.Set(oidctest.Knobs{AuthTime: time.Now().Add(-10 * time.Minute)})
	if out := b.signIn(t, true); out.Reason != "LOGIN_FAILED" {
		t.Errorf("auth_time 10 minutes old: reason %q, want LOGIN_FAILED", out.Reason)
	}
	b.idp.Set(oidctest.Knobs{OmitAuthTime: true})
	if out := b.signIn(t, true); out.Reason != "LOGIN_FAILED" {
		t.Errorf("auth_time missing: reason %q, want LOGIN_FAILED", out.Reason)
	}
	// Without max_age, a missing auth_time is fine but never counts as recent.
	out := b.signIn(t, false)
	s, err := b.browser.Authenticate(context.Background(), out.Secret)
	if err != nil || s.SignedInWithin(authnapp.RecentSignIn) {
		t.Fatalf("session without auth_time: recent=%v err=%v, want not recent", s.SignedInWithin(authnapp.RecentSignIn), err)
	}
	b.idp.Set(oidctest.Knobs{})
	out = b.signIn(t, true)
	if s, err = b.browser.Authenticate(context.Background(), out.Secret); err != nil || !s.SignedInWithin(authnapp.RecentSignIn) {
		t.Fatalf("session after a recent sign-in: recent=%v err=%v", s.SignedInWithin(authnapp.RecentSignIn), err)
	}
}

func TestHR152_ReturnPathsAreFromTheList(t *testing.T) {
	b := newBrowserEnv(t)
	for _, next := range []string{"//evil.example", "https://evil.example/account", `/\evil.example`, "/account/../oauth2", "/accountx", "/"} {
		if _, err := b.browser.Start(context.Background(), authnapp.BrowserStart{Org: b.org.String(), Next: next}); !errors.Is(err, authnapp.ErrSignInUnavailable) {
			t.Errorf("next %q: %v, want ErrSignInUnavailable", next, err)
		}
	}
	for _, in := range []authnapp.BrowserStart{
		{Org: "not-an-org"}, {Org: ids.New[ids.Org]().String()}, {Org: b.org.String(), Provider: "other"},
	} {
		if _, err := b.browser.Start(context.Background(), in); !errors.Is(err, authnapp.ErrSignInUnavailable) {
			t.Errorf("start %+v: %v, want ErrSignInUnavailable", in, err)
		}
	}
	if out := b.mustSignIn(t); out.Next != authnapp.AccountPath {
		t.Errorf("default return path %q", out.Next)
	}
}

func TestHR152_OnlyMembersGetASession(t *testing.T) {
	b := newBrowserEnv(t)
	b.idp.SignIn(oidctest.User{Subject: "mallory", Email: "mallory@example.test", EmailVerified: true})
	if out := b.signIn(t, false); out.Reason != "NOT_A_MEMBER" || out.Secret != "" {
		t.Errorf("non-member: %+v", out)
	}
	b.idp.SignIn(oidctest.User{Subject: "alice", Email: "alice@example.test", EmailVerified: true})
	b.exec(t, b.org, "UPDATE pc.users SET state = 'DISABLED' WHERE id = $1", b.user)
	if out := b.signIn(t, false); out.Reason != "USER_DISABLED" || out.Secret != "" {
		t.Errorf("disabled user: %+v", out)
	}
	if n := b.count(t, "SELECT count(*) FROM pc.sessions"); n != 0 {
		t.Errorf("%d sessions created for refused sign-ins", n)
	}
}

func TestHR150_SessionsAreHashedBoundedAndChecked(t *testing.T) {
	b := newBrowserEnv(t)
	ctx := context.Background()
	out := b.mustSignIn(t)
	s, err := b.browser.Authenticate(ctx, out.Secret)
	if err != nil || s.Credential != authnapp.CredBrowserSession || s.User() != b.user || s.ID != out.Session || s.Session != s.ID {
		t.Fatalf("authenticate: %+v %v", s, err)
	}
	sum := sha256.Sum256([]byte(out.Secret))
	if n := b.count(t, "SELECT count(*) FROM pc.sessions WHERE secret_hash = $1", sum[:]); n != 1 {
		t.Fatal("the session is not stored by the hash of its secret")
	}
	if n := b.count(t, "SELECT count(*) FROM pc.sessions WHERE position($1::bytea IN secret_hash) > 0", []byte(out.Secret)); n != 0 {
		t.Fatal("the plain secret is stored")
	}
	if n := b.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.authn.login'"); n != 1 {
		t.Errorf("%d login audit events, want 1", n)
	}

	// A value that was never issued is not a session (no fixation).
	planted, _ := credential.New(credential.BrowserSession, "", b.org)
	if _, err := b.browser.Authenticate(ctx, planted.Reveal()); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("planted cookie: %v", err)
	}
	if again := b.mustSignIn(t); again.Secret == out.Secret {
		t.Error("two sign-ins share a secret")
	}

	idle := b.mustSignIn(t)
	b.d.AdminExec(t, "UPDATE pc.sessions SET last_seen_at = now() - interval '31 minutes' WHERE id = $1", idle.Session)
	if _, err := b.browser.Authenticate(ctx, idle.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) || b.endReason(t, idle.Session) != "IDLE" {
		t.Errorf("idle session: %v, end reason %q", err, b.endReason(t, idle.Session))
	}
	old := b.mustSignIn(t)
	b.d.AdminExec(t, "UPDATE pc.sessions SET expires_at = now() - interval '1 second' WHERE id = $1", old.Session)
	if _, err := b.browser.Authenticate(ctx, old.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) || b.endReason(t, old.Session) != "EXPIRED" {
		t.Errorf("expired session: %v, end reason %q", err, b.endReason(t, old.Session))
	}

	b.exec(t, b.org, "UPDATE pc.users SET state = 'DISABLED' WHERE id = $1", b.user)
	if _, err := b.browser.Authenticate(ctx, out.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("disabled user: %v", err)
	}
	b.exec(t, b.org, "UPDATE pc.users SET state = 'ACTIVE' WHERE id = $1", b.user)
	b.d.AdminExec(t, "UPDATE pc.orgs SET state = 'SUSPENDED' WHERE id = $1", b.org)
	if _, err := b.browser.Authenticate(ctx, out.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("suspended org: %v", err)
	}
}

func TestHR150_AUserHasAtMostTenSessions(t *testing.T) {
	b := newBrowserEnv(t)
	first := b.mustSignIn(t)
	for range authnapp.MaxBrowserSessions {
		b.mustSignIn(t)
	}
	if n := b.count(t, "SELECT count(*) FROM pc.sessions WHERE state = 'ACTIVE'"); n != authnapp.MaxBrowserSessions {
		t.Errorf("%d active sessions, want %d", n, authnapp.MaxBrowserSessions)
	}
	if r := b.endReason(t, first.Session); r != "SESSION_LIMIT" {
		t.Errorf("oldest session end reason %q, want SESSION_LIMIT", r)
	}
	if _, err := b.browser.Authenticate(context.Background(), first.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("oldest session still works: %v", err)
	}
}

func TestHR150_RoleChangeRotatesAndOldSecretsExpire(t *testing.T) {
	b := newBrowserEnv(t)
	ctx := context.Background()
	out := b.mustSignIn(t)
	if s, err := b.browser.Authenticate(ctx, out.Secret); err != nil || s.Rotated != "" {
		t.Fatalf("unchanged roles rotated: %+v %v", s, err)
	}
	b.exec(t, b.org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, 'auditor', $3, 'ORG', 'test')`, b.org, ids.NewV7(), b.user)
	s, err := b.browser.Authenticate(ctx, out.Secret)
	if err != nil || s.Rotated == "" || s.Rotated == out.Secret {
		t.Fatalf("role change did not rotate: %+v %v", s, err)
	}
	next := s.Rotated
	// The old secret works during the grace, without rotating again.
	if s, err := b.browser.Authenticate(ctx, out.Secret); err != nil || s.Rotated != "" {
		t.Fatalf("old secret inside the grace: %+v %v", s, err)
	}
	if s, err := b.browser.Authenticate(ctx, next); err != nil || s.Rotated != "" {
		t.Fatalf("new secret: %+v %v", s, err)
	}
	// After the grace, the old secret is a theft signal: the session ends.
	b.d.AdminExec(t, "UPDATE pc.sessions SET rotated_at = now() - interval '2 minutes' WHERE id = $1", out.Session)
	if _, err := b.browser.Authenticate(ctx, out.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Fatalf("old secret after the grace: %v", err)
	}
	if r := b.endReason(t, out.Session); r != "REUSE" {
		t.Errorf("end reason %q, want REUSE", r)
	}
	if _, err := b.browser.Authenticate(ctx, next); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("new secret still works after reuse: %v", err)
	}
	if n := b.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.authn.session_reuse'"); n != 1 {
		t.Errorf("%d reuse audit events, want 1", n)
	}
}

func TestT051_SignedOutAndRevokedCookiesAreDead(t *testing.T) {
	b := newBrowserEnv(t)
	ctx := context.Background()
	out := b.mustSignIn(t)
	if err := b.browser.Logout(ctx, out.Secret); err != nil {
		t.Fatal(err)
	}
	if _, err := b.browser.Authenticate(ctx, out.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) || b.endReason(t, out.Session) != "LOGOUT" {
		t.Errorf("cookie after sign-out: %v, end reason %q", err, b.endReason(t, out.Session))
	}
	if err := b.browser.Logout(ctx, out.Secret); err != nil {
		t.Errorf("signing out twice: %v", err)
	}

	mine := b.mustSignIn(t)
	other := b.mustSignIn(t)
	s, err := b.browser.Authenticate(ctx, mine.Secret)
	if err != nil {
		t.Fatal(err)
	}
	list, err := b.browser.ListSessions(ctx, s)
	if err != nil || len(list) != 3 {
		t.Fatalf("list: %d sessions, %v", len(list), err)
	}
	for _, x := range list {
		if x.Current != (x.ID == mine.Session) || x.UserAgent != "test-agent" {
			t.Errorf("listed session %+v", x)
		}
	}
	if err := b.browser.RevokeSession(ctx, s, other.Session); err != nil {
		t.Fatal(err)
	}
	if _, err := b.browser.Authenticate(ctx, other.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) || b.endReason(t, other.Session) != "REVOKED" {
		t.Errorf("revoked session: %v", err)
	}
	// Another user's session id is indistinguishable from none (IDOR).
	bob := ids.NewV7()
	b.exec(t, b.org, `INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')`, b.org, bob)
	bobSession := ids.NewV7()
	b.exec(t, b.org, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'test', $4, now() + interval '1 hour')`, b.org, bobSession, bob, sum32(9))
	for _, id := range []ids.UUID{bobSession, ids.NewV7()} {
		if err := b.browser.RevokeSession(ctx, s, id); !errors.Is(err, authnapp.ErrSessionNotFound) {
			t.Errorf("revoke %s: %v, want ErrSessionNotFound", id, err)
		}
	}
	if b.endReason(t, bobSession) != "" {
		t.Error("another user's session was ended")
	}
}

func sum32(b byte) []byte {
	s := sha256.Sum256([]byte{b})
	return s[:]
}
