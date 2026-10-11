// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// wfx is an org with a run whose transaction has an unknown outcome, and
// two people: ann and ben.
type wfx struct {
	t                    *testing.T
	d                    *dbtest.DB
	p                    *db.Pool
	org                  ids.OrgID
	txn                  ids.UUID
	ann, ben             ids.UUID
	run, grant, instance ids.UUID
	w                    *waitlist.Writer
}

func (f *wfx) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *wfx) tx(fn func(context.Context, db.TenantTx) error) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, fn); err != nil {
		f.t.Fatal(err)
	}
}

func (f *wfx) state(entry ids.UUID) string {
	f.t.Helper()
	var s string
	f.d.AdminQueryRow(f.t, "SELECT state FROM pc.waitlist_entries WHERE id = $1", []any{entry}, &s)
	return s
}

func newWFx(t *testing.T) *wfx {
	t.Helper()
	d := dbtest.New(t)
	f := &wfx{
		t: t, d: d, p: d.AppPool(t), org: ids.New[ids.Org](), txn: ids.NewV7(), ann: ids.NewV7(), ben: ids.NewV7(),
		run: ids.NewV7(), grant: ids.NewV7(), instance: ids.NewV7(),
	}
	f.w = waitlist.NewWriter(f.p)
	agent, env, run := ids.NewV7(), ids.NewV7(), f.run
	f.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", f.org)
	for _, u := range []ids.UUID{f.ann, f.ben} {
		f.exec(`INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)`, f.org, u, u.String())
	}
	f.exec("INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'dev', 'Dev', 'DEVELOPMENT')", f.org, env)
	f.exec("INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", f.org, agent)
	f.exec(`INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, f.org, f.instance, agent, f.instance.String()[:36]+"0000000")
	f.exec(`INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, f.org, f.grant, agent, f.ann, env)
	f.exec(`INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, principal_user_id, principal_source,
		grant_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $6, 'launcher', $7, now() + interval '8 hours')`,
		f.org, run, agent, f.instance, env, f.ann, f.grant)
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'OK', 'gw', 'OPEN')`, f.org, f.txn, run, ids.NewV7(), make([]byte, 32))
	return f
}

// as is a person with roles at org scope.
func (f *wfx) as(user ids.UUID, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Bindings: bs},
	})
}

func (f *wfx) reconciliation() ids.UUID {
	f.t.Helper()
	var id ids.UUID
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, err = pgwaitlist.OpenReconciliation(ctx, tx, f.org, f.txn, pgwaitlist.System)
		return err
	})
	return id
}

// overdue moves an entry's times into the past.
func (f *wfx) overdue(entry ids.UUID) {
	f.d.AdminExec(f.t, `UPDATE pc.waitlist_entries SET created_at = now() - interval '100 days',
		deadline_at = now() - interval '1 minute' WHERE id = $1`, entry)
}

func (f *wfx) expire() int {
	f.t.Helper()
	var n int
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		n, err = pgwaitlist.ExpireEntries(ctx, tx, f.org)
		return err
	})
	return n
}

// TestHR003_AnUnknownOutcomeWaitsForReconciliationAndNeverExpires: one open
// RECONCILIATION entry per transaction, which stays open past its deadline.
func TestHR003_AnUnknownOutcomeWaitsForReconciliationAndNeverExpires(t *testing.T) {
	f := newWFx(t)
	first := f.reconciliation()
	if again := f.reconciliation(); again != first {
		t.Fatalf("a second producer call opened %s, want %s", again, first)
	}
	var kind, subject string
	var priority int
	f.d.AdminQueryRow(t, `SELECT kind, subject_type || ':' || subject_id, priority FROM pc.waitlist_entries WHERE id = $1`,
		[]any{first}, &kind, &subject, &priority)
	if kind != "RECONCILIATION" || subject != "transaction:"+f.txn.String() || priority != 1 {
		t.Fatalf("entry %s %s %d", kind, subject, priority)
	}
	f.overdue(first)
	if n := f.expire(); n != 0 || f.state(first) != "OPEN" {
		t.Fatalf("an unknown outcome resolved by itself: %d %s", n, f.state(first))
	}
}

// TestHR177_ToolReviewsExpireAndChangeNothing: an overdue tool review ends
// EXPIRED, audited; the version stays as it was.
func TestHR177_ToolReviewsExpireAndChangeNothing(t *testing.T) {
	f := newWFx(t)
	var review ids.UUID
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		review, err = pgwaitlist.OpenToolReview(ctx, tx, f.org, ids.NewV7(), "pc.mock-payments", "1.0.0", pgwaitlist.System)
		return err
	})
	if n := f.expire(); n != 0 {
		t.Fatalf("a tool review expired before its deadline: %d", n)
	}
	f.overdue(review)
	if n := f.expire(); n != 1 || f.state(review) != "EXPIRED" {
		t.Fatalf("overdue review: %d %s", n, f.state(review))
	}
	var events int
	f.d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.waitlist.entry_expired'`, []any{f.org}, &events)
	if events != 1 {
		t.Fatalf("%d expiry events", events)
	}
}

// TestHR177_AssignmentShowsWhoIsWorkingAndDecidesNothing: only someone who
// can decide the entry takes it (here a Reconciler, a holder of
// transaction.reconcile, G0 M7); a reader who cannot decide is refused, a
// stranger gets "not found", and a closed entry cannot be taken.
func TestHR177_AssignmentShowsWhoIsWorkingAndDecidesNothing(t *testing.T) {
	f := newWFx(t)
	entry := f.reconciliation()
	e, err := f.w.Assign(f.as(f.ann, td.RoleReconciler), entry, false)
	if err != nil || e.Assignee != f.ann || e.AssignedAt == nil || e.State != "OPEN" {
		t.Fatalf("assign: %+v, %v", e, err)
	}
	for _, reader := range []td.RoleName{td.RoleApprover, td.RoleResponder} {
		if _, err := f.w.Assign(f.as(f.ben, reader), entry, false); !errors.Is(err, waitlist.ErrNotDecider) {
			t.Fatalf("a %s, who reads but cannot decide: %v", reader, err)
		}
	}
	if _, err := f.w.Assign(f.as(f.ben), entry, false); !errors.Is(err, waitlist.ErrEntryNotFound) {
		t.Fatalf("a stranger: %v", err)
	}
	if e, err := f.w.Assign(f.as(f.ben, td.RoleSecurityAdmin), entry, true); err != nil || !e.Assignee.IsZero() || e.AssignedAt != nil {
		t.Fatalf("unassign: %+v, %v", e, err)
	}

	var review ids.UUID
	version := ids.NewV7()
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		review, err = pgwaitlist.OpenToolReview(ctx, tx, f.org, version, "pc.mock-payments", "1.0.0", pgwaitlist.System)
		return err
	})
	if _, err := f.w.Assign(f.as(f.ann, td.RoleResponder), review, false); !errors.Is(err, waitlist.ErrNotDecider) {
		t.Fatalf("a tool review needs package.activate: %v", err)
	}
	if e, err := f.w.Assign(f.as(f.ben, td.RolePolicyPublisher), review, false); err != nil || e.Assignee != f.ben {
		t.Fatalf("a policy publisher takes the review: %+v, %v", e, err)
	}
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		return pgwaitlist.CloseToolReview(ctx, tx, f.org, version, "ACTIVE", "user:"+f.ben.String())
	})
	if f.state(review) != "APPROVED" {
		t.Fatalf("an activated version's review: %s", f.state(review))
	}
	if _, err := f.w.Assign(f.as(f.ben, td.RolePolicyPublisher), review, false); !errors.Is(err, waitlist.ErrEntryClosed) {
		t.Fatalf("a closed entry: %v", err)
	}
}

// denied adds a transaction of the run with decision and reason.
func (f *wfx) denied(decision, reason string) ids.UUID {
	f.t.Helper()
	id := ids.NewV7()
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', $6, $7, 'gw', 'OPEN')`, f.org, id, f.run, ids.NewV7(), make([]byte, 32), decision, reason)
	return id
}

// TestHR176_AnAccessRequestGrantsNothing (F051, decision 10): the run's
// launcher files one for the run's grant, with an untrusted note and a
// 7-day deadline; anyone else gets "run not found"; a second request
// returns the open one; the grant is unchanged.
func TestHR176_AnAccessRequestGrantsNothing(t *testing.T) {
	f := newWFx(t)
	txn := f.denied("DENY", "OPERATION_NOT_GRANTED")
	e, err := f.w.RequestAccess(f.as(f.ann), f.run, "need refunds", &txn)
	if err != nil || e.Kind != "ACCESS_REQUEST" || e.SubjectType != "grant" || e.SubjectID != f.grant || e.State != "OPEN" ||
		e.Untrusted["note"] != "need refunds" || e.Evidence["reason"] != "OPERATION_NOT_GRANTED" || e.Evidence["grant_revision"] != "1" {
		t.Fatalf("request: %+v, %v", e, err)
	}
	var days int
	f.d.AdminQueryRow(t, "SELECT round(extract(epoch FROM deadline_at - created_at) / 86400)::int FROM pc.waitlist_entries WHERE id = $1",
		[]any{e.ID}, &days)
	if days != 7 {
		t.Fatalf("deadline %d days", days)
	}
	if _, err := f.w.RequestAccess(f.as(f.ben, td.RoleGrantIssuer), f.run, "me too", nil); !errors.Is(err, waitlist.ErrRunNotFound) {
		t.Fatalf("someone else's run: %v", err)
	}
	if again, err := f.w.RequestAccess(f.as(f.ann), f.run, "again", nil); err != nil || again.ID != e.ID {
		t.Fatalf("a second request: %+v, %v", again, err)
	}
	var rev int
	f.d.AdminQueryRow(t, "SELECT current_revision FROM pc.grants WHERE id = $1", []any{f.grant}, &rev)
	if rev != 1 {
		t.Fatalf("an access request changed the grant: revision %d", rev)
	}

	// Only a grant.issue holder dismisses it.
	if _, err := f.w.DismissAccessRequest(f.as(f.ben, td.RoleApprover), e.ID, "no"); err == nil {
		t.Fatal("an approver dismissed an access request")
	}
	if d, err := f.w.DismissAccessRequest(f.as(f.ben, td.RoleGrantIssuer), e.ID, "use the refunds agent"); err != nil ||
		d.State != "REJECTED" || d.DecidedBy != "user:"+f.ben.String() || d.DecisionReason != "use the refunds agent" {
		t.Fatalf("dismiss: %+v, %v", d, err)
	}
	if _, err := f.w.DismissAccessRequest(f.as(f.ben, td.RoleGrantIssuer), e.ID, "again"); !errors.Is(err, waitlist.ErrNotAccessRequest) {
		t.Fatalf("a closed request: %v", err)
	}
}

// TestHR176_AWorkloadCitesOnlyItsOwnScopeDenials (decision 10): the run's
// own instance may file, citing a denial about the grant's scope, at most
// 3 times per run; another instance gets "run not found".
func TestHR176_AWorkloadCitesOnlyItsOwnScopeDenials(t *testing.T) {
	f := newWFx(t)
	scope := f.denied("DENY", "TARGET_NOT_GRANTED")
	if _, err := f.w.RequestWorkloadAccess(context.Background(), f.org, ids.NewV7(), f.run, scope, "x"); !errors.Is(err, waitlist.ErrRunNotFound) {
		t.Fatalf("another instance: %v", err)
	}
	for _, other := range []ids.UUID{f.denied("ALLOW", "OK"), f.denied("DENY", "OUTSIDE_GUARDRAIL")} {
		if _, err := f.w.RequestWorkloadAccess(context.Background(), f.org, f.instance, f.run, other, "x"); !errors.Is(err, waitlist.ErrNotScopeDenial) {
			t.Fatalf("not a scope denial: %v", err)
		}
	}
	for i := range 3 {
		e, err := f.w.RequestWorkloadAccess(context.Background(), f.org, f.instance, f.run, scope, "please")
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		if _, err := f.w.DismissAccessRequest(f.as(f.ben, td.RoleGrantIssuer), e.ID, "no"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.w.RequestWorkloadAccess(context.Background(), f.org, f.instance, f.run, scope, "please"); !errors.Is(err, waitlist.ErrAccessRequestLimit) {
		t.Fatalf("the fourth request: %v", err)
	}
}
