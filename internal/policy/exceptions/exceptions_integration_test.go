// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exceptions_test

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// notifier records the notifications it is asked to send.
type notifier struct{ sent []napp.Message }

func (n *notifier) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.sent = append(n.sent, m)
	return napp.Enqueued{}, nil
}

// changes records the change requests asked for.
type changes struct {
	asked []exceptions.Summary
	base  ids.UUID
	sum   [32]byte
	fail  error
}

func (c *changes) Request(_ context.Context, kind papp.ChangeKind, subject, base ids.UUID, binding [32]byte, summary any,
) (papp.ChangeRequest, error) {
	if c.fail != nil {
		return papp.ChangeRequest{}, c.fail
	}
	c.asked, c.base, c.sum = append(c.asked, summary.(exceptions.Summary)), base, binding
	return papp.ChangeRequest{ID: ids.NewV7(), Kind: kind, Subject: subject, URL: "/policy-changes/" + subject.String()}, nil
}

type fixture struct {
	d                 *dbtest.DB
	p                 *db.Pool
	org               ids.OrgID
	alice, bob, agent ids.UUID
	published         ids.UUID
	svc               *exceptions.Service
	n                 *notifier
	c                 *changes
}

const op = "payments.refund.create"

func rules() []pdomain.Rule {
	return []pdomain.Rule{
		{
			ID: "hold-large", Kind: pdomain.RequireApproval, Summary: "Hold large refunds", Operations: []string{"payments.refund.*"},
			When: "true", Reason: "LARGE_REFUND", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1}, Exceptable: true,
		},
		{ID: "no-huge", Kind: pdomain.Forbid, Summary: "No huge refunds", Operations: []string{op}, When: "true", Reason: "HUGE"},
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{
		d: d, p: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), bob: ids.NewV7(), agent: ids.NewV7(),
		published: ids.NewV7(), n: &notifier{}, c: &changes{},
	}
	f.svc = &exceptions.Service{Pool: f.p, Notify: f.n, Changes: f.c}
	raw, err := json.Marshal(pdomain.Bundle{ID: "refunds", Version: 1, Rules: rules()}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	policy := ids.NewV7()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'exc')", []any{f.org}},
		{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", []any{f.org, f.alice}},
		{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", []any{f.org, f.bob}},
		{"INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'refunder', 'DISCOVERED', 'test')", []any{f.org, f.agent}},
		{"INSERT INTO pc.policies (org_id, id, bundle_id) VALUES ($1, $2, 'refunds')", []any{f.org, policy}},
		{`INSERT INTO pc.policy_versions (org_id, id, policy_id, version, bundle, state, created_by, published_by, published_at)
			VALUES ($1, $2, $3, 1, $4, 'PUBLISHED', 'test', 'test', now())`, []any{f.org, f.published, policy, raw}},
	} {
		f.exec(t, s.sql, s.args...)
	}
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (f *fixture) as(user ids.UUID, cred tenancy.Credential, roles ...td.RoleName) context.Context {
	bs := make([]td.Binding, 0, len(roles))
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Bindings: bs},
		Credential: cred,
	})
}

func (f *fixture) request() exceptions.Request {
	return exceptions.Request{
		Rule: "hold-large", Agent: f.agent, Operations: []string{op}, Reason: "Quarter-end backlog of reviewed refunds.",
		ExpiresIn: 7 * 24 * time.Hour,
	}
}

// activate runs the change request's apply callback as the approving
// transaction would.
func (f *fixture) activate(t *testing.T, id ids.UUID) (exceptions.Exception, error) {
	t.Helper()
	var x exceptions.Exception
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		x, err = f.svc.Activate(ctx, tx, f.org, id)
		return err
	})
	return x, err
}

func (f *fixture) active(t *testing.T) []pdomain.Exception {
	t.Helper()
	var out []pdomain.Exception
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = exceptions.ActiveFor(ctx, tx, f.org, f.agent)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestT102_OnlyAPersonAsksForAnExceptableRule: an API key, a person
// without policy.exception.request, a rule that is not exceptable, an
// unknown rule, an operation outside the rule's scope, a prefix and an
// expiry beyond 30 days are refused. A policy author's request is PENDING,
// audited and bound to an EXCEPTION change request against the published
// version; nothing applies before it is approved.
func TestT102_OnlyAPersonAsksForAnExceptableRule(t *testing.T) {
	f := newFixture(t)
	req := f.request()
	if _, _, err := f.svc.RequestException(f.as(f.alice, tenancy.CredAPIKey, td.RolePolicyAuthor), req); !errors.Is(err, exceptions.ErrHumanOnly) {
		t.Fatalf("an API key asked: %v", err)
	}
	for _, r := range []td.RoleName{td.RoleViewer, td.RoleApprover, td.RoleAgentOwner} {
		if _, _, err := f.svc.RequestException(f.as(f.alice, tenancy.CredAccessToken, r), req); !errors.Is(err, td.ErrPermissionDenied(td.PermPolicyExceptionRequest)) {
			t.Fatalf("%s asked: %v", r, err)
		}
	}
	author := f.as(f.alice, tenancy.CredAccessToken, td.RolePolicyAuthor)
	for name, tt := range map[string]struct {
		mod  func(*exceptions.Request)
		want error
	}{
		"a rule that is not exceptable": {func(r *exceptions.Request) { r.Rule = "no-huge" }, exceptions.ErrNotExceptable},
		"an unknown rule":               {func(r *exceptions.Request) { r.Rule = "nope" }, exceptions.ErrRuleNotFound},
		"an operation outside the rule": {func(r *exceptions.Request) { r.Operations = []string{"payments.charge.create"} }, exceptions.ErrOperation},
		"a prefix":                      {func(r *exceptions.Request) { r.Operations = []string{"payments.refund.*"} }, exceptions.ErrInvalid},
		"31 days":                       {func(r *exceptions.Request) { r.ExpiresIn = 31 * 24 * time.Hour }, exceptions.ErrInvalid},
		"no reason":                     {func(r *exceptions.Request) { r.Reason = "   " }, exceptions.ErrInvalid},
		"an unknown agent":              {func(r *exceptions.Request) { r.Agent = ids.NewV7() }, exceptions.ErrAgentNotFound},
		"an unknown owner":              {func(r *exceptions.Request) { o := ids.NewV7(); r.Owner = &o }, exceptions.ErrOwner},
	} {
		bad := req
		tt.mod(&bad)
		if _, _, err := f.svc.RequestException(author, bad); !errors.Is(err, tt.want) {
			t.Errorf("%s: %v, want %v", name, err, tt.want)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM pc.policy_exceptions`); n != 0 {
		t.Fatalf("%d exceptions stored by refused requests", n)
	}
	x, cr, err := f.svc.RequestException(author, req)
	if err != nil || x.State != exceptions.StatePending || x.RequestedBy != f.alice || x.OwnerID != f.alice || cr.ID.IsZero() {
		t.Fatalf("exception %+v, change request %+v (%v)", x, cr, err)
	}
	rule := rules()[0]
	if d := pdomain.RuleDigest(rule); hex.EncodeToString(x.RuleDigest) != hex.EncodeToString(d[:]) {
		t.Fatal("the stored rule digest is not the rule's")
	}
	xd, _ := exceptions.Digest(x)
	want, _ := papp.ChangeBinding(papp.ChangeException, f.org, x.ID, f.published, xd, f.c.asked[0])
	if f.c.base != f.published || f.c.sum != want || len(f.c.asked) != 1 || f.c.asked[0].Kind != "EXCEPTION" {
		t.Fatalf("change request base %s digest %x summary %+v", f.c.base, f.c.sum, f.c.asked)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.policy.exception_requested'`); n != 1 {
		t.Fatalf("%d audited requests", n)
	}
	if got := f.active(t); len(got) != 0 {
		t.Fatalf("a pending exception applies: %+v", got)
	}
	// A request needs the change-request mechanism (fail closed).
	if _, _, err := (&exceptions.Service{Pool: f.p}).RequestException(author, req); !errors.Is(err, exceptions.ErrNoChangeRequests) {
		t.Fatalf("a request without change requests: %v", err)
	}
}

// TestHR235_ExpiryIsTheDatabaseClocks: activation sets the expiry from the
// database clock, at most 30 days and never past the requested expiry; an
// active exception stops applying when the database clock passes it, the
// sweep records it as EXPIRED and the owner hears once a day before. No
// transition goes back, and pc_app cannot extend an expiry.
func TestHR235_ExpiryIsTheDatabaseClocks(t *testing.T) {
	f := newFixture(t)
	x, _, err := f.svc.RequestException(f.as(f.alice, tenancy.CredAccessToken, td.RolePolicyAuthor), f.request())
	if err != nil {
		t.Fatal(err)
	}
	x, err = f.activate(t, x.ID)
	if err != nil || x.State != exceptions.StateActive || x.ExpiresAt == nil || !x.ExpiresAt.Equal(x.RequestedExpiry) {
		t.Fatalf("activated %+v (%v)", x, err)
	}
	if _, err := f.activate(t, x.ID); !errors.Is(err, exceptions.ErrNotPending) {
		t.Fatalf("activated twice: %v", err)
	}
	if got := f.active(t); len(got) != 1 || got[0].ID != x.ID.String() || got[0].Rule != "hold-large" {
		t.Fatalf("active %+v", got)
	}
	if len(f.n.sent) != 1 || f.n.sent[0].Type != "policy.exception_activated" || f.n.sent[0].Personal[0] != f.alice ||
		!f.n.sent[0].PersonalOnly || f.n.sent[0].Params["agent"] != f.agent.String() {
		t.Fatalf("notifications %+v", f.n.sent)
	}
	// pc_app may not move an expiry, nor bring a closed exception back.
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `UPDATE pc.policy_exceptions SET expires_at = expires_at + interval '1 day' WHERE id = $1`, x.ID)
		return err
	}); err == nil {
		t.Fatal("the expiry of an active exception was extended")
	}

	// One exception ended an hour ago, one ends within the day.
	ended, soon := ids.NewV7(), ids.NewV7()
	for _, s := range []struct {
		id      ids.UUID
		created string
		ends    string
	}{{ended, "2 hours", "-1 hour"}, {soon, "1 hour", "2 hours"}} {
		f.d.AdminExec(t, `INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations, reason,
			owner_id, requested_by, requested_expiry)
			SELECT org_id, $2, bundle_id, rule_id, rule_digest, agent_id, operations, reason, $3, requested_by, now() + interval '1 day'
			FROM pc.policy_exceptions WHERE id = $1`, x.ID, s.id, f.bob)
		f.d.AdminExec(t, `UPDATE pc.policy_exceptions SET state = 'ACTIVE' WHERE id = $1`, s.id)
		backdate(t, f.d, s.id, s.created, s.ends)
	}
	got := f.active(t)
	if len(got) != 2 || got[0].ID == ended.String() || got[1].ID == ended.String() {
		t.Fatalf("active %+v: an exception past its expiry applies", got)
	}
	n, err := f.svc.Sweep(context.Background(), f.org)
	if err != nil || n != 1 {
		t.Fatalf("swept %d (%v)", n, err)
	}
	if st := f.count(t, `SELECT count(*) FROM pc.policy_exceptions WHERE id = $1 AND state = 'EXPIRED'`, ended); st != 1 {
		t.Fatal("the ended exception was not recorded as EXPIRED")
	}
	expiring := 0
	for _, m := range f.n.sent {
		if m.Type == "policy.exception_expiring" {
			expiring++
			if m.Personal[0] != f.bob || m.DedupeKey != "policy.exception_expiring:"+soon.String() || m.Params["exception"] != soon.String() {
				t.Fatalf("expiring notice %+v", m)
			}
		}
	}
	if expiring != 1 {
		t.Fatalf("%d expiring notices", expiring)
	}
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `UPDATE pc.policy_exceptions SET state = 'ACTIVE' WHERE id = $1`, ended)
		return err
	}); err == nil {
		t.Fatal("an expired exception came back")
	}
	l, err := f.svc.GetException(f.as(f.bob, tenancy.CredAccessToken, td.RoleViewer, td.RolePolicyPublisher), ended)
	if err != nil || l.EffectiveState != exceptions.StateExpired {
		t.Fatalf("get %+v (%v)", l, err)
	}
}

// TestHR235_RevokeIsAPublishersAnyTime: only a person holding
// policy.publish revokes, with a reason; a revoked exception applies no
// more and is never revoked or activated again.
func TestHR235_RevokeIsAPublishersAnyTime(t *testing.T) {
	f := newFixture(t)
	x, _, err := f.svc.RequestException(f.as(f.alice, tenancy.CredAccessToken, td.RolePolicyAuthor), f.request())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.activate(t, x.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RevokeException(f.as(f.alice, tenancy.CredAccessToken, td.RolePolicyAuthor), x.ID, "done"); !errors.Is(err, td.ErrPermissionDenied(td.PermPolicyPublish)) {
		t.Fatalf("an author revoked: %v", err)
	}
	if _, err := f.svc.RevokeException(f.as(f.bob, tenancy.CredAPIKey, td.RolePolicyPublisher), x.ID, "done"); !errors.Is(err, exceptions.ErrHumanOnly) {
		t.Fatalf("an API key revoked: %v", err)
	}
	publisher := f.as(f.bob, tenancy.CredAccessToken, td.RolePolicyPublisher)
	r, err := f.svc.RevokeException(publisher, x.ID, "Backlog cleared.")
	if err != nil || r.State != exceptions.StateRevoked || *r.RevokedBy != f.bob {
		t.Fatalf("revoked %+v (%v)", r, err)
	}
	if got := f.active(t); len(got) != 0 {
		t.Fatalf("a revoked exception applies: %+v", got)
	}
	if _, err := f.svc.RevokeException(publisher, x.ID, "again"); !errors.Is(err, exceptions.ErrNotOpen) {
		t.Fatalf("revoked twice: %v", err)
	}
	if _, err := f.svc.RevokeException(publisher, ids.NewV7(), "again"); !errors.Is(err, exceptions.ErrNotFound) {
		t.Fatalf("revoked an unknown exception: %v", err)
	}
	// A pending one is revoked too, and can then never be activated.
	y, _, err := f.svc.RequestException(f.as(f.alice, tenancy.CredAccessToken, td.RolePolicyAuthor), f.request())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RevokeException(publisher, y.ID, "Not needed."); err != nil {
		t.Fatal(err)
	}
	if _, err := f.activate(t, y.ID); !errors.Is(err, exceptions.ErrRevoked) {
		t.Fatalf("a revoked request was activated: %v", err)
	}
	rows, _, err := f.svc.ListExceptions(publisher, exceptions.Filter{Agent: &f.agent}, 0, "")
	if err != nil || len(rows) != 2 || rows[0].ID != y.ID {
		t.Fatalf("list %+v (%v)", rows, err)
	}
	st := exceptions.StateRevoked
	if rows, _, err := f.svc.ListExceptions(publisher, exceptions.Filter{State: &st}, 0, ""); err != nil || len(rows) != 2 {
		t.Fatalf("list revoked %+v (%v)", rows, err)
	}
	if _, _, err := f.svc.ListExceptions(f.as(f.alice, tenancy.CredAccessToken, td.RoleApprover), exceptions.Filter{}, 0, ""); !errors.Is(err, td.ErrPermissionDenied(td.PermPolicyRead)) {
		t.Fatalf("an approver listed: %v", err)
	}
}

// TestT102_ApprovalRechecksTheBase (D23): at the last confirmation the
// apply callback refuses with BASE_CHANGED when the rule changed or is no
// longer exceptable in the published version or the agent was retired,
// and with EXPIRED when the requested expiry has passed; nothing becomes
// active.
func TestT102_ApprovalRechecksTheBase(t *testing.T) {
	author := func(f *fixture) context.Context { return f.as(f.alice, tenancy.CredAccessToken, td.RolePolicyAuthor) }
	for name, tt := range map[string]struct {
		change func(t *testing.T, f *fixture, x exceptions.Exception)
		want   error
	}{
		"rule changed": {func(t *testing.T, f *fixture, _ exceptions.Exception) {
			rs := rules()
			rs[0].When = "false"
			f.republish(t, rs)
		}, exceptions.ErrBaseChanged},
		"rule no longer exceptable": {func(t *testing.T, f *fixture, _ exceptions.Exception) {
			rs := rules()
			rs[0].Exceptable = false
			f.republish(t, rs)
		}, exceptions.ErrBaseChanged},
		"rule removed": {func(t *testing.T, f *fixture, _ exceptions.Exception) {
			f.republish(t, rules()[1:])
		}, exceptions.ErrBaseChanged},
		"agent retired": {func(t *testing.T, f *fixture, _ exceptions.Exception) {
			f.d.AdminExec(t, `UPDATE pc.agents SET state = 'RETIRED', retired_at = now() WHERE org_id = $1 AND id = $2`, f.org, f.agent)
		}, exceptions.ErrBaseChanged},
		"requested expiry passed": {func(t *testing.T, f *fixture, x exceptions.Exception) {
			f.d.AdminExec(t, `ALTER TABLE pc.policy_exceptions DISABLE TRIGGER policy_exceptions_transition`)
			f.d.AdminExec(t, `UPDATE pc.policy_exceptions SET created_at = now() - interval '2 hours', requested_expiry = now() - interval '1 hour'
				WHERE id = $1`, x.ID)
			f.d.AdminExec(t, `ALTER TABLE pc.policy_exceptions ENABLE TRIGGER policy_exceptions_transition`)
		}, exceptions.ErrRequestExpired},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			x, _, err := f.svc.RequestException(author(f), f.request())
			if err != nil {
				t.Fatal(err)
			}
			tt.change(t, f, x)
			if _, err := f.activate(t, x.ID); !errors.Is(err, tt.want) {
				t.Fatalf("activate: %v, want %v", err, tt.want)
			}
			if n := f.count(t, `SELECT count(*) FROM pc.policy_exceptions WHERE state = 'ACTIVE'`); n != 0 {
				t.Fatalf("%d active exceptions", n)
			}
		})
	}
}

// republish replaces the published version with rules (test setup).
func (f *fixture) republish(t *testing.T, rs []pdomain.Rule) {
	t.Helper()
	raw, err := json.Marshal(pdomain.Bundle{ID: "refunds", Version: 2, Rules: rs}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE pc.policy_versions SET state = 'SUPERSEDED' WHERE org_id = $1 AND id = $2`, f.org, f.published)
	f.exec(t, `INSERT INTO pc.policy_versions (org_id, id, policy_id, version, bundle, state, created_by, published_by, published_at)
		SELECT org_id, $2, policy_id, 2, $3, 'PUBLISHED', 'test', 'test', now() FROM pc.policy_versions WHERE org_id = $1 AND id = $4`,
		f.org, ids.NewV7(), raw, f.published)
}

// backdate moves an active exception's times as the database clock would
// have set them: activated (and requested) `ago` before now, ending
// `ends` from now (test setup; pc_app never can).
func backdate(t *testing.T, d *dbtest.DB, id ids.UUID, ago, ends string) {
	t.Helper()
	d.AdminExec(t, `ALTER TABLE pc.policy_exceptions DISABLE TRIGGER policy_exceptions_transition`)
	d.AdminExec(t, `UPDATE pc.policy_exceptions SET created_at = now() - $2::interval, activated_at = now() - $2::interval,
		requested_expiry = now() + $3::interval, expires_at = now() + $3::interval WHERE id = $1`, id, ago, ends)
	d.AdminExec(t, `ALTER TABLE pc.policy_exceptions ENABLE TRIGGER policy_exceptions_transition`)
}

// TestHR235_AnExceptionIsInsertedPendingOnly (D33): pc_app cannot insert
// an exception that is already active, revoked or dated, nor one longer
// than 30 days; whatever it says, the database's time and PENDING are
// stored.
func TestHR235_AnExceptionIsInsertedPendingOnly(t *testing.T) {
	f := newFixture(t)
	d := pdomain.RuleDigest(rules()[0])
	insert := func(state, created, expiry string) error {
		return f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations,
				reason, owner_id, requested_by, requested_expiry, state, activated_at, expires_at, created_at)
				VALUES ($1, $2, 'refunds', 'hold-large', $3, $4, ARRAY['payments.refund.create'], 'r', $5, $5,
					`+expiry+`, $6, now(), `+expiry+`, `+created+`)`,
				f.org, ids.NewV7(), d[:], f.agent, f.alice, state)
			return err
		})
	}
	for name, err := range map[string]error{
		"ACTIVE":               insert("ACTIVE", "now()", "now() + interval '1 hour'"),
		"dated in the future":  insert("ACTIVE", "now() + interval '70 years'", "now() + interval '70 years 1 hour'"),
		"longer than 30 days":  insert("PENDING", "now()", "now() + interval '31 days'"),
		"REVOKED from the off": insert("REVOKED", "now()", "now() + interval '1 hour'"),
	} {
		if !db.IsCheckViolation(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := insert("PENDING", "now() - interval '1 day'", "now() + interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.policy_exceptions WHERE state = 'PENDING' AND activated_at IS NULL
		AND expires_at IS NULL AND created_at > now() - interval '1 minute'`); n != 1 {
		t.Fatalf("%d exceptions stored as inserted by the database", n)
	}
}

// TestT102_ListingPagesFromTheFirst: the first page (no token) starts at the
// newest exception, and the token continues after the last one shown, so
// every exception is listed once.
func TestT102_ListingPagesFromTheFirst(t *testing.T) {
	f := newFixture(t)
	author := f.as(f.alice, tenancy.CredAccessToken, td.RolePolicyAuthor)
	var made []ids.UUID
	for range 3 {
		x, _, err := f.svc.RequestException(author, f.request())
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, x.ID)
	}
	reader := f.as(f.bob, tenancy.CredAccessToken, td.RoleViewer, td.RolePolicyPublisher)
	first, next, err := f.svc.ListExceptions(reader, exceptions.Filter{}, 2, "")
	if err != nil || len(first) != 2 || next == "" || first[0].ID != made[2] || first[1].ID != made[1] {
		t.Fatalf("first page %+v next %q (%v)", first, next, err)
	}
	rest, next, err := f.svc.ListExceptions(reader, exceptions.Filter{}, 2, next)
	if err != nil || len(rest) != 1 || next != "" || rest[0].ID != made[0] {
		t.Fatalf("second page %+v next %q (%v)", rest, next, err)
	}
}
