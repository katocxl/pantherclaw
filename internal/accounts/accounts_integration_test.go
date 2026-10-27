// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package accounts_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const issuer = "https://idp.example.test"

type fixture struct {
	d     *dbtest.DB
	pool  *db.Pool
	store *accounts.Store
	ents  *entitlements.Service
}

func newFixture(t *testing.T, mode entitlements.Mode) *fixture {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	lic := entitlements.LicenceFunc(func(context.Context) (billing.Entitlements, error) { return billing.CommunityEntitlements(), nil })
	ents, err := entitlements.New(p, lic, mode, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{d: d, pool: p, store: accounts.NewStore(p), ents: ents}
}

func (f *fixture) account(t *testing.T, subject, email string, verified bool) accounts.Account {
	t.Helper()
	a, err := f.store.Resolve(context.Background(), accounts.Identity{
		Issuer: issuer, Subject: subject, Email: email, EmailVerified: verified, Name: subject,
	}, "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *fixture) org(t *testing.T, name string) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	f.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", org, name)
	return org
}

func (f *fixture) user(t *testing.T, org ids.OrgID, subject string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	f.exec(t, org, `INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, $3, $4, $4 || '@example.test')`,
		org, id, issuer, subject)
	return id
}

func (f *fixture) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) count(t *testing.T, org ids.OrgID, sql string, args ...any) int {
	t.Helper()
	var n int
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func as(a accounts.Account) context.Context {
	return accounts.WithCaller(context.Background(), accounts.Caller{Account: a.ID, Provider: "test", IP: "198.51.100.7"})
}

func wantReason(t *testing.T, what string, err error, reason string) {
	t.Helper()
	if pcerr.ReasonOf(err) != reason {
		t.Errorf("%s: err = %v, want %s", what, err, reason)
	}
}

// TestHR348_AccountsAreKeyedByIssuerAndSubjectAndNeverLinkedByEmail.
func TestHR348_AccountsAreKeyedByIssuerAndSubjectAndNeverLinkedByEmail(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	ctx := context.Background()
	a := f.account(t, "alice", "alice@example.test", true)
	again := f.account(t, "alice", "alice@new.example.test", true)
	if again.ID != a.ID || again.Email != "alice@new.example.test" {
		t.Errorf("the same identity resolved to %+v", again)
	}
	other, err := f.store.Resolve(ctx, accounts.Identity{
		Issuer: "https://other-idp.example.test", Subject: "alice", Email: "alice@example.test", EmailVerified: true,
	}, "")
	if err != nil || other.ID == a.ID {
		t.Fatalf("another issuer's identity with the same email: %+v, %v", other, err)
	}
	org := f.org(t, "acme")
	u := f.user(t, org, "alice")
	// A user links only to the account of its own issuer and subject.
	link := func(account ids.UUID) error {
		return f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return accounts.LinkUser(ctx, tx, account, u)
		})
	}
	if err := link(other.ID); err == nil {
		t.Error("a user was linked to another issuer's account")
	}
	if err := link(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := link(a.ID); err != nil {
		t.Errorf("linking again: %v", err)
	}
	err = f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if err := db.SetAccountContext(ctx, tx, other.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "UPDATE pc.users SET account_id = $1 WHERE org_id = $2 AND id = $3", other.ID, org, u)
		return err
	})
	if err == nil {
		t.Error("a user's account link was changed")
	}
}

// TestHR349_MembershipsComeOnlyFromTheAuditedListerForThatAccount, and the
// account tables are invisible outside the account context or the accounts
// purpose (D41).
func TestHR349_MembershipsComeOnlyFromTheAuditedListerForThatAccount(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	ctx := context.Background()
	a := f.account(t, "alice", "alice@example.test", true)
	b := f.account(t, "bob", "bob@example.test", true)
	one, two, gone := f.org(t, "Zeta"), f.org(t, "alpha"), f.org(t, "gone")
	u1 := f.user(t, one, "alice")
	f.user(t, two, "alice")
	f.user(t, gone, "alice")
	f.user(t, one, "bob")
	disabled := f.org(t, "disabled-user")
	du := f.user(t, disabled, "alice")
	f.exec(t, disabled, "UPDATE pc.users SET state = 'DISABLED' WHERE org_id = $1 AND id = $2", disabled, du)
	f.d.AdminExec(t, "UPDATE pc.orgs SET state = 'SUSPENDED' WHERE id = $1", gone)
	ms, err := f.store.Memberships(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []ids.OrgID
	for _, m := range ms {
		got = append(got, m.Org)
	}
	if !slices.Equal(got, []ids.OrgID{two, one}) || ms[1].User != u1 {
		t.Errorf("memberships = %+v, want alpha then Zeta", ms)
	}
	if bm, err := f.store.Memberships(ctx, b.ID); err != nil || len(bm) != 1 || bm[0].Org != one {
		t.Errorf("bob's memberships = %+v, %v", bm, err)
	}
	// Without the account the purpose lists nothing.
	refs, err := f.pool.CrossOrgListWith(ctx, db.ListAccountMemberships, 100, db.ListerParams{})
	if err != nil || len(refs) != 0 {
		t.Errorf("lister without an account: %v, %v", refs, err)
	}
	var audited int
	f.d.AdminQueryRow(t, "SELECT count(*)::int FROM pc.cross_org_list_audit WHERE purpose = 'account_memberships' AND subject = $1",
		[]any{a.ID.String()}, &audited)
	if audited != 1 {
		t.Errorf("audit rows naming alice's account = %d", audited)
	}
	// D41: a tenant transaction sees no account row; the account context
	// sees its own only.
	if n := f.count(t, one, "SELECT count(*)::int FROM pc.accounts"); n != 0 {
		t.Errorf("a tenant transaction sees %d accounts", n)
	}
	for _, table := range []string{"pc.account_sessions", "pc.account_events", "pc.account_login_requests"} {
		if n := f.count(t, one, "SELECT count(*)::int FROM "+table); n != 0 {
			t.Errorf("a tenant transaction sees %d rows of %s", n, table)
		}
	}
	err = f.pool.InTenantTx(ctx, one, func(ctx context.Context, tx db.TenantTx) error {
		if err := db.SetAccountContext(ctx, tx, a.ID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*)::int FROM pc.accounts").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("alice's context sees %d accounts", n)
		}
		if err := tx.QueryRow(ctx, "SELECT count(*)::int FROM pc.account_events WHERE account_id = $1", b.ID).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("alice's context sees bob's events")
		}
		_, err := tx.Exec(ctx, "UPDATE pc.accounts SET email = 'x@example.test' WHERE id = $1", b.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := f.store.Get(ctx, b.ID); got.Email != "bob@example.test" {
		t.Error("alice's context changed bob's account")
	}
	err = f.pool.InGlobalTx(ctx, db.GlobalHealth, func(ctx context.Context, tx db.GlobalTx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*)::int FROM pc.accounts").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("another global purpose sees %d accounts", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The app role has no plain path around the policies.
	var bypass bool
	f.d.AdminQueryRow(t, "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'pc_app'", nil, &bypass)
	if bypass {
		t.Error("pc_app bypasses RLS")
	}
	for _, tbl := range []string{"accounts", "account_sessions", "account_events", "account_login_requests"} {
		var forced bool
		f.d.AdminQueryRow(t, "SELECT relforcerowsecurity FROM pg_class WHERE oid = ('pc.' || $1)::regclass", []any{tbl}, &forced)
		if !forced {
			t.Errorf("pc.%s does not force RLS", tbl)
		}
	}
}

// TestHR350_AccountSessionsCallOnlyAllowListedProcedures: the allow list is
// exactly D8's plus GetDeletionRecord (G0 M13 D34), and an account
// caller carries no org caller, so every
// org-scoped use case refuses it.
func TestHR350_AccountSessionsCallOnlyAllowListedProcedures(t *testing.T) {
	declared, err := protoperms.Declared(filepath.Join("..", "..", "proto"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"/pantherclaw.v1.AccessService/WhoAmI": true, "/pantherclaw.v1.AccessService/AcceptInvitation": true,
		"/pantherclaw.v1.TenancyService/CreateOrg": true, "/pantherclaw.v1.TenancyService/ListMyOrgs": true,
		// G0 M13 D34: only records of deletions this account requested.
		"/pantherclaw.v1.DataRequestService/GetDeletionRecord": true,
	}
	for proc := range declared {
		allowed := accounts.AllowedProcedure(proc)
		isAccount := len(proc) > len("/pantherclaw.v1.AccountService/") && proc[:len("/pantherclaw.v1.AccountService/")] == "/pantherclaw.v1.AccountService/"
		if allowed != (want[proc] || isAccount) {
			t.Errorf("%s allowed=%v", proc, allowed)
		}
	}
	f := newFixture(t, entitlements.ModeExternal)
	ctx := as(f.account(t, "alice", "alice@example.test", true))
	if _, err := tapp.CallerFrom(ctx); !errors.Is(err, tapp.ErrNoCaller) {
		t.Errorf("an account session is an org caller: %v", err)
	}
	if _, err := tapp.NewHierarchy(f.pool, nil).GetOrg(ctx); err == nil {
		t.Error("an account session read an org")
	}
	if _, err := f.ents.Get(ctx); err == nil {
		t.Error("an account session read a plan")
	}
}

// TestHR351_CreateOrgNeedsSelfServeAVerifiedEmailAndStaysWithinTheLimits.
func TestHR351_CreateOrgNeedsSelfServeAVerifiedEmailAndStaysWithinTheLimits(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	ctx := context.Background()
	cfg := accounts.DefaultSignup()
	cfg.TermsVersion, cfg.DPAVersion = "2026-10", "2026-10"
	in := accounts.NewOrg{Name: "Acme", Slug: "acme", TermsVersion: "2026-10", DPAVersion: "2026-10"}
	alice := f.account(t, "alice", "alice@example.test", true)
	if _, err := accounts.NewSignup(f.store, f.ents, cfg).CreateOrg(as(alice), in); !errors.Is(err, accounts.ErrSignupDisabled) {
		t.Errorf("self-serve off: %v", err)
	}
	cfg.SelfServe = true
	s := accounts.NewSignup(f.store, f.ents, cfg)
	if _, err := s.CreateOrg(ctx, in); !errors.Is(err, accounts.ErrNoAccount) {
		t.Errorf("no account: %v", err)
	}
	unverified := f.account(t, "mallory", "alice@example.test", false)
	if _, err := s.CreateOrg(as(unverified), in); !errors.Is(err, accounts.ErrEmailUnverified) {
		t.Errorf("unverified email: %v", err)
	}
	old := in
	old.TermsVersion = "2025-01"
	if _, err := s.CreateOrg(as(alice), old); !errors.Is(err, accounts.ErrTerms) {
		t.Errorf("old terms: %v", err)
	}
	out, err := s.CreateOrg(as(alice), in)
	if err != nil {
		t.Fatal(err)
	}
	// The creator is the org's Org Admin, linked to the account, and the
	// terms are recorded.
	if n := f.count(t, out.Org, `SELECT count(*)::int FROM pc.role_bindings b JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id
		WHERE b.org_id = $1 AND b.role = 'org_admin' AND u.account_id = $2`, out.Org, alice.ID); n != 1 {
		t.Errorf("org admins linked to alice = %d", n)
	}
	if n := f.count(t, out.Org, "SELECT count(*)::int FROM pc.org_terms_acceptances WHERE org_id = $1 AND terms_version = '2026-10' AND dpa_version = '2026-10'", out.Org); n != 1 {
		t.Errorf("terms acceptances = %d", n)
	}
	if n := f.count(t, out.Org, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.tenancy.org_created'", out.Org); n != 1 {
		t.Errorf("org_created audits = %d", n)
	}
	if ms, _ := s.ListMyOrgs(as(alice)); len(ms) != 1 || ms[0].Org != out.Org || ms[0].Slug != "acme" {
		t.Errorf("ListMyOrgs = %+v", ms)
	}
	// One org without a plan per account (D8).
	if _, err := s.CreateOrg(as(alice), in); !errors.Is(err, accounts.ErrAccountOrgLimit) {
		t.Errorf("second unplanned org: %v", err)
	}
	if err := f.ents.ApplyPlan(ctx, out.Org, entitlements.Snapshot{
		PlanID: "team", Edition: "team", Status: entitlements.StatusActive, EventID: "evt_1", EventAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateOrg(as(alice), in)
	if err != nil {
		t.Fatalf("second org once the first has a plan: %v", err)
	}
	if err := f.ents.ApplyPlan(ctx, second.Org, entitlements.Snapshot{
		PlanID: "team", Edition: "team", Status: entitlements.StatusActive, EventID: "evt_2", EventAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrg(as(alice), in); err != nil {
		t.Fatalf("third org: %v", err)
	}
	if _, err := s.CreateOrg(as(alice), in); !errors.Is(err, accounts.ErrAccountOrgLimit) {
		t.Errorf("fourth org: %v", err)
	}
	// The terms row must name the user's own account (L2).
	err = f.pool.InTenantTx(ctx, out.Org, func(ctx context.Context, tx db.TenantTx) error {
		var u ids.UUID
		if err := tx.QueryRow(ctx, "SELECT id FROM pc.users WHERE org_id = $1", out.Org).Scan(&u); err != nil {
			return err
		}
		return dbq.New(tx).InsertTermsAcceptance(ctx, dbq.InsertTermsAcceptanceParams{
			OrgID: out.Org, ID: ids.NewV7(), AccountID: unverified.ID, UserID: u, TermsVersion: "x", DpaVersion: "x",
		})
	})
	if err == nil {
		t.Error("terms recorded for another account")
	}
}

// TestT164_OrgCreationIsRateLimitedPerAccountAndAddress, and slugs are
// labels, not identifiers (no existence oracle).
func TestT164_OrgCreationIsRateLimitedPerAccountAndAddress(t *testing.T) {
	f := newFixture(t, entitlements.ModeOff)
	cfg := accounts.DefaultSignup()
	cfg.SelfServe, cfg.MaxOrgsPerAccount, cfg.MaxUnplannedPerAccount, cfg.PerAccountPerHour, cfg.PerIPPerHour = true, 100, 100, 3, 5
	s := accounts.NewSignup(f.store, f.ents, cfg)
	in := accounts.NewOrg{Name: "Acme", Slug: "acme", TermsVersion: "1", DPAVersion: "1"}
	alice := f.account(t, "alice", "alice@example.test", true)
	for i := range 3 {
		if _, err := s.CreateOrg(as(alice), in); err != nil {
			t.Fatalf("org %d: %v", i, err)
		}
	}
	if _, err := s.CreateOrg(as(alice), in); !errors.Is(err, accounts.ErrRateLimited) {
		t.Errorf("fourth within the hour: %v", err)
	}
	// Another account behind the same address reaches its limit: 3 created
	// and 1 refused, then bob's one more makes 5 attempts.
	bob := f.account(t, "bob", "bob@example.test", true)
	if _, err := s.CreateOrg(as(bob), in); err != nil {
		t.Fatalf("bob's first: %v", err)
	}
	if _, err := s.CreateOrg(as(bob), in); !errors.Is(err, accounts.ErrRateLimited) {
		t.Errorf("same address after its limit: %v", err)
	}
	carol := f.account(t, "carol", "carol@example.test", true)
	ctx := accounts.WithCaller(context.Background(), accounts.Caller{Account: carol.ID, IP: "203.0.113.9"})
	if out, err := s.CreateOrg(ctx, in); err != nil || out.Slug != "acme" {
		t.Errorf("another address with the same slug: %+v, %v", out, err)
	}
	wantReason(t, "rate limit", accounts.ErrRateLimited, "RATE_LIMITED")
}

// TestHR352_InvitationsInTheBrowserNeedTheVerifiedEmailAreSingleUseAndExpire.
func TestHR352_InvitationsInTheBrowserNeedTheVerifiedEmailAreSingleUseAndExpire(t *testing.T) {
	f := newFixture(t, entitlements.ModeOff)
	ctx := context.Background()
	iv := accounts.NewInvitations(f.store, f.ents)
	org := f.org(t, "acme")
	invite := func(email, ttl string) string {
		tok, err := credential.New(credential.Invitation, "", org)
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, org, `INSERT INTO pc.invitations (org_id, id, email, roles, token_hash, created_by, expires_at)
			VALUES ($1, $2, $3, '{developer}', $4, 'test', now() + $5::interval)`, org, ids.NewV7(), email, tok.Hash(), ttl)
		return tok.Reveal()
	}
	alice := f.account(t, "alice", "Alice@Example.test", true)
	unverified := f.account(t, "alice-unverified", "alice@example.test", false)
	mallory := f.account(t, "mallory", "mallory@example.test", true)
	tok := invite("alice@example.test", "1 day")
	if _, err := iv.Accept(ctx, mallory.ID, tok, ""); !errors.Is(err, accounts.ErrEmailMismatch) {
		t.Errorf("another email: %v", err)
	}
	if _, err := iv.Accept(ctx, unverified.ID, tok, ""); !errors.Is(err, accounts.ErrEmailMismatch) {
		t.Errorf("unverified email: %v", err)
	}
	got, err := iv.Accept(ctx, alice.ID, tok, "")
	if err != nil || got.Org != org {
		t.Fatalf("accept: %+v, %v", got, err)
	}
	if n := f.count(t, org, `SELECT count(*)::int FROM pc.invitations WHERE org_id = $1 AND accepted_via = 'BROWSER'
		AND accepted_account_id = $2 AND accepted_user_id = $3`, org, alice.ID, got.User); n != 1 {
		t.Errorf("accepted invitation rows = %d", n)
	}
	if n := f.count(t, org, `SELECT count(*)::int FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2 AND role = 'developer'`, org, got.User); n != 1 {
		t.Errorf("developer bindings = %d", n)
	}
	if _, err := iv.Accept(ctx, alice.ID, tok, ""); !errors.Is(err, accounts.ErrInvitationInvalid) {
		t.Errorf("second use: %v", err)
	}
	if _, err := iv.Accept(ctx, alice.ID, invite("alice@example.test", "-1 minute"), ""); !errors.Is(err, accounts.ErrInvitationInvalid) {
		t.Errorf("expired: %v", err)
	}
	if _, err := iv.Accept(ctx, alice.ID, invite("alice@example.test", "1 day"), ""); !errors.Is(err, accounts.ErrAlreadyMember) {
		t.Errorf("already a member: %v", err)
	}
	if _, err := iv.Accept(ctx, alice.ID, "pci_not_a_token", ""); !errors.Is(err, accounts.ErrInvitationInvalid) {
		t.Errorf("garbage token: %v", err)
	}
}

// TestT165_AStolenInvitationLinkIsUselessToAnotherAccount: the mismatch is
// refused, recorded in the org's ledger, and the invitation stays pending
// for its owner.
func TestT165_AStolenInvitationLinkIsUselessToAnotherAccount(t *testing.T) {
	f := newFixture(t, entitlements.ModeOff)
	ctx := context.Background()
	iv := accounts.NewInvitations(f.store, f.ents)
	org := f.org(t, "acme")
	tok, err := credential.New(credential.Invitation, "", org)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, org, `INSERT INTO pc.invitations (org_id, id, email, roles, token_hash, created_by, expires_at)
		VALUES ($1, $2, 'alice@example.test', '{org_admin}', $3, 'test', now() + interval '1 day')`, org, ids.NewV7(), tok.Hash())
	thief := f.account(t, "thief", "thief@example.test", true)
	if _, err := iv.Accept(ctx, thief.ID, tok.Reveal(), ""); !errors.Is(err, accounts.ErrEmailMismatch) {
		t.Fatalf("thief: %v", err)
	}
	if n := f.count(t, org, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.access.invitation_refused'", org); n != 1 {
		t.Errorf("refusals recorded = %d", n)
	}
	if n := f.count(t, org, "SELECT count(*)::int FROM pc.invitations WHERE org_id = $1 AND state = 'PENDING'", org); n != 1 {
		t.Error("the invitation was spent by the thief")
	}
	if n := f.count(t, org, "SELECT count(*)::int FROM pc.users WHERE org_id = $1", org); n != 0 {
		t.Error("the thief became a member")
	}
}

// TestHR360_MemberLimitHoldsForBrowserInvitations.
func TestHR360_MemberLimitHoldsForBrowserInvitations(t *testing.T) {
	f := newFixture(t, entitlements.ModeExternal)
	ctx := context.Background()
	org := f.org(t, "acme")
	f.user(t, org, "first")
	if err := f.ents.ApplyPlan(ctx, org, entitlements.Snapshot{
		PlanID: "team", Edition: "team", Status: entitlements.StatusActive, EventID: "e", EventAt: time.Now(),
		Limits: entitlements.Limits{MaxMembers: 1},
	}); err != nil {
		t.Fatal(err)
	}
	tok, err := credential.New(credential.Invitation, "", org)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, org, `INSERT INTO pc.invitations (org_id, id, email, roles, token_hash, created_by, expires_at)
		VALUES ($1, $2, 'alice@example.test', '{}', $3, 'test', now() + interval '1 day')`, org, ids.NewV7(), tok.Hash())
	alice := f.account(t, "alice", "alice@example.test", true)
	if _, err := accounts.NewInvitations(f.store, f.ents).Accept(ctx, alice.ID, tok.Reveal(), ""); !errors.Is(err, accounts.ErrMemberLimit) {
		t.Errorf("over the member limit: %v", err)
	}
	// And at invitation time, through the access use case.
	a := tapp.NewAccess(f.pool, nil).WithEntitlements(f.ents)
	admin := tapp.WithCaller(ctx, tapp.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	if _, _, err := a.CreateInvitation(admin, "bob@example.test", nil, 0); pcerr.ReasonOf(err) != "PLAN_LIMIT" {
		t.Errorf("invitation over the member limit: %v", err)
	}
	// Environments too.
	if err := f.ents.ApplyPlan(ctx, org, entitlements.Snapshot{
		PlanID: "team", Edition: "team", Status: entitlements.StatusActive, EventID: "e2", EventAt: time.Now(),
		Limits: entitlements.Limits{MaxEnvironments: 1},
	}); err != nil {
		t.Fatal(err)
	}
	h := tapp.NewHierarchy(f.pool, f.ents)
	if _, err := h.CreateEnvironment(admin, td.TeamID{}, td.Production, tapp.NewEntity{Slug: "prod", Name: "Prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CreateEnvironment(admin, td.TeamID{}, td.Staging, tapp.NewEntity{Slug: "stage", Name: "Stage"}); pcerr.ReasonOf(err) != "PLAN_LIMIT" {
		t.Errorf("environment over the limit: %v", err)
	}
}
