// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/response/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// notes records the notifications the use cases queue.
type notes struct {
	mu    sync.Mutex
	types []string
}

func (n *notes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.types = append(n.types, m.Type)
	return napp.Enqueued{}, nil
}

func (n *notes) list() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return strings.Join(n.types, ",")
}

type env struct {
	d     *dbtest.DB
	pool  *db.Pool
	svc   *app.Service
	notes *notes
	org   ids.OrgID
}

// person is a user with one active security key.
type person struct {
	id, key ids.UUID
	ctx     context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{d: d, pool: d.AppPool(t), notes: &notes{}, org: ids.New[ids.Org]()}
	e.svc = app.New(e.pool, e.notes, "https://pc.example.test")
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'response')", e.org)
	return e
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) query(t *testing.T, sql string, args []any, dest ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(dest...)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// otherOrg is a second org in the same database.
func (e *env) otherOrg(t *testing.T) *env {
	t.Helper()
	o := &env{d: e.d, pool: e.pool, notes: &notes{}, org: ids.New[ids.Org]()}
	o.svc = app.New(o.pool, o.notes, "https://pc.example.test")
	o.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", o.org)
	return o
}

// person adds a user with a security key, holding role.
func (e *env) person(t *testing.T, name string, role td.RoleName) person {
	t.Helper()
	p := person{id: ids.NewV7(), key: ids.NewV7()}
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, p.id, name)
	e.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		e.org, p.key, p.id, []byte("cred-"+name+"-0123456789"), []byte("public-key-of-"+name+"-0123456789abcdefghijklmnop"))
	p.ctx = e.caller(td.KindUser, p.id, role)
	return p
}

func (e *env) caller(kind td.PrincipalKind, id ids.UUID, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: kind, ID: id},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
}

// now is a step-up made just now with p's key.
func (p person) now() app.StepUp { return app.StepUp{Credential: p.key, At: time.Now()} }

func (e *env) epoch(t *testing.T) int64 {
	t.Helper()
	var n int64
	e.query(t, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", []any{e.org}, &n)
	return n
}

// audited returns a detail of the latest ledger entry of an audit event.
func (e *env) audited(t *testing.T, name, detail string) string {
	t.Helper()
	var v *string
	e.query(t, `SELECT (SELECT convert_from(body, 'UTF8')::jsonb -> 'details' ->> $2::text FROM pc.ledger_entries
		WHERE kind = 'audit.' || $1::text ORDER BY occurred_at DESC, id DESC LIMIT 1)`, []any{name, detail}, &v)
	if v == nil {
		return ""
	}
	return *v
}

func is(err, want error) bool { return errors.Is(err, want) }

func denied(err error) bool {
	var pe *pcerr.Error
	return errors.As(err, &pe) && pe.Code() == pcerr.PermissionDenied
}

// TestHR113_OnePersonWithAFreshStepUpEngagesTheKillSwitch: engaging is one
// person with a fresh step-up and a reason; it raises the epoch (HR-002),
// records who, when and why, writes the ledger with what else the kill
// switch did, and notifies.
func TestHR113_OnePersonWithAFreshStepUpEngagesTheKillSwitch(t *testing.T) {
	e := newEnv(t)
	alice := e.person(t, "alice", td.RoleEmergency)
	before, err := e.svc.Status(alice.ctx)
	if err != nil {
		t.Fatal(err)
	}
	const reason = "leak <script>alert(1)</script>" // untrusted text, stored as given
	st, err := e.svc.Engage(alice.ctx, alice.now(), reason)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Engaged || st.Epoch != before.Epoch+1 || st.EngagedBy != "user:"+alice.id.String() || st.EngagedAt == nil ||
		st.Reason != reason || st.PageURL != "https://pc.example.test/containment?org="+e.org.String() {
		t.Fatalf("after engage: %+v", st)
	}
	if e.epoch(t) != st.Epoch {
		t.Fatal("the stored epoch did not move")
	}
	if got := e.audited(t, "security.kill_switch_engaged", "provider_revocation"); got != "not_supported" {
		t.Fatalf("provider_revocation = %q", got)
	}
	if got := e.audited(t, "security.kill_switch_engaged", "automations_paused"); got != "none_exist" {
		t.Fatalf("automations_paused = %q", got)
	}
	if got := e.audited(t, "security.kill_switch_engaged", "key_id"); got != alice.key.String() {
		t.Fatalf("key_id = %q", got)
	}
	if e.notes.list() != "security.kill_switch_engaged" {
		t.Fatalf("notifications: %s", e.notes.list())
	}
	if _, err := e.svc.Engage(alice.ctx, alice.now(), "again"); !is(err, app.ErrAlreadyEngaged) {
		t.Fatalf("engaging twice: %v", err)
	}
}

// TestHR113_EngagingNeedsTheRoleAKeyAndAFreshStepUp: no permission, a
// service account, no step-up, an old step-up, someone else's key, a
// suspended key and a missing or long reason are all refused, and nothing
// changes.
func TestHR113_EngagingNeedsTheRoleAKeyAndAFreshStepUp(t *testing.T) {
	e := newEnv(t)
	alice := e.person(t, "alice", td.RoleEmergency)
	bob := e.person(t, "bob", td.RoleEmergency)
	admin := e.person(t, "carol", td.RoleSecurityAdmin)
	cases := []struct {
		name   string
		ctx    context.Context
		su     app.StepUp
		reason string
		want   func(error) bool
	}{
		{"security admin", admin.ctx, admin.now(), "x", denied},
		{"service account", e.caller(td.KindServiceAccount, ids.NewV7(), td.RoleEmergency), alice.now(), "x", denied},
		{"no step-up", alice.ctx, app.StepUp{}, "x", func(err error) bool { return is(err, app.ErrStepUp) }},
		{
			"old step-up", alice.ctx,
			app.StepUp{Credential: alice.key, At: time.Now().Add(-app.StepUpWithin - time.Minute)},
			"x",
			func(err error) bool { return is(err, app.ErrStepUp) },
		},
		{
			"future step-up", alice.ctx,
			app.StepUp{Credential: alice.key, At: time.Now().Add(time.Hour)},
			"x",
			func(err error) bool { return is(err, app.ErrStepUp) },
		},
		{"someone else's key", alice.ctx, bob.now(), "x", func(err error) bool { return is(err, app.ErrStepUp) }},
		{"no reason", alice.ctx, alice.now(), "", func(err error) bool { return is(err, app.ErrReason) }},
		{"long reason", alice.ctx, alice.now(), strings.Repeat("é", app.MaxReason+1), func(err error) bool { return is(err, app.ErrReason) }},
	}
	for _, c := range cases {
		if _, err := e.svc.Engage(c.ctx, c.su, c.reason); !c.want(err) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	e.exec(t, `UPDATE pc.webauthn_credentials SET state = 'SUSPENDED', state_reason = 'CLONE_SUSPECTED', changed_at = now(),
		changed_by = 'test' WHERE id = $1`, alice.key)
	if _, err := e.svc.Engage(alice.ctx, alice.now(), "x"); !is(err, app.ErrStepUp) {
		t.Errorf("suspended key: %v", err)
	}
	if st, err := e.svc.Status(bob.ctx); err != nil || st.Engaged || st.Epoch != 1 {
		t.Fatalf("a refused engage changed something: %+v %v", st, err)
	}
	// The longest reason fits, and the ledger keeps it cut at 512 bytes.
	long := strings.Repeat("é", app.MaxReason)
	if _, err := e.svc.Engage(bob.ctx, bob.now(), long); err != nil {
		t.Fatal(err)
	}
	if got := e.audited(t, "security.kill_switch_engaged", "reason"); got != strings.Repeat("é", 256) {
		t.Fatalf("audited reason has %d bytes", len(got))
	}
	if e.audited(t, "security.kill_switch_engaged", "reason_truncated") != "true" {
		t.Fatal("the cut reason is not marked")
	}
}

// TestHR113_RestoringNeedsASecondPersonWithTheirOwnKey: the proposer cannot
// confirm; a second person with a fresh step-up does, which clears the
// kill switch and raises the epoch (HR-002).
func TestHR113_RestoringNeedsASecondPersonWithTheirOwnKey(t *testing.T) {
	e := newEnv(t)
	alice := e.person(t, "alice", td.RoleEmergency)
	bob := e.person(t, "bob", td.RoleEmergency)
	if _, err := e.svc.ProposeRestore(alice.ctx, alice.now(), "too early"); !is(err, app.ErrNotEngaged) {
		t.Fatalf("propose while not engaged: %v", err)
	}
	engaged, err := e.svc.Engage(alice.ctx, alice.now(), "incident 42")
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.svc.ProposeRestore(alice.ctx, alice.now(), "contained")
	if err != nil {
		t.Fatal(err)
	}
	if d := p.ExpiresAt.Sub(p.CreatedAt); d != app.RestoreWindow {
		t.Fatalf("window %s", d)
	}
	if _, err := e.svc.ProposeRestore(bob.ctx, bob.now(), "also"); !is(err, app.ErrRestorePending) {
		t.Fatalf("a second proposal: %v", err)
	}
	if _, err := e.svc.ConfirmRestore(alice.ctx, alice.now(), p.ID); !is(err, app.ErrSamePerson) {
		t.Fatalf("the proposer confirmed: %v", err)
	}
	if _, err := e.svc.ConfirmRestore(bob.ctx, alice.now(), p.ID); !is(err, app.ErrStepUp) {
		t.Fatalf("confirmed with the proposer's key: %v", err)
	}
	if _, err := e.svc.ConfirmRestore(bob.ctx, app.StepUp{Credential: bob.key, At: time.Now().Add(-6 * time.Minute)}, p.ID); !is(err, app.ErrStepUp) {
		t.Fatalf("confirmed with an old step-up: %v", err)
	}
	if st, _ := e.svc.Status(bob.ctx); !st.Engaged || st.Pending == nil || st.Pending.ID != p.ID {
		t.Fatalf("refused confirmations changed something: %+v", st)
	}
	st, err := e.svc.ConfirmRestore(bob.ctx, bob.now(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Engaged || st.Epoch != engaged.Epoch+1 || st.Pending != nil || st.EngagedBy != "" || st.Reason != "" {
		t.Fatalf("after restore: %+v", st)
	}
	var state string
	var decider ids.UUID
	e.query(t, "SELECT state, decided_by FROM pc.kill_switch_requests WHERE id = $1", []any{p.ID}, &state, &decider)
	if state != "CONFIRMED" || decider != bob.id {
		t.Fatalf("proposal %s decided by %s", state, decider)
	}
	if got := e.audited(t, "security.kill_switch_restored", "proposed_by"); got != alice.id.String() {
		t.Fatalf("restored proposed_by = %q", got)
	}
	if got := e.notes.list(); got != "security.kill_switch_engaged,security.kill_switch_restore_proposed,security.kill_switch_restored" {
		t.Fatalf("notifications: %s", got)
	}
	if _, err := e.svc.ConfirmRestore(bob.ctx, bob.now(), p.ID); !is(err, app.ErrRestoreGone) {
		t.Fatalf("confirming twice: %v", err)
	}
}

// TestHR113_AProposalExpiresAndEitherPersonCanCancel: an expired proposal
// cannot be confirmed and frees the slot; anyone holding the permission
// can cancel a pending one without a step-up, and the switch stays on.
func TestHR113_AProposalExpiresAndEitherPersonCanCancel(t *testing.T) {
	e := newEnv(t)
	alice := e.person(t, "alice", td.RoleEmergency)
	bob := e.person(t, "bob", td.RoleEmergency)
	viewer := e.person(t, "dan", td.RoleViewer)
	if _, err := e.svc.Engage(alice.ctx, alice.now(), "incident"); err != nil {
		t.Fatal(err)
	}
	p, err := e.svc.ProposeRestore(alice.ctx, alice.now(), "contained")
	if err != nil {
		t.Fatal(err)
	}
	e.d.AdminExec(t, "UPDATE pc.kill_switch_requests SET created_at = now() - interval '31 minutes', expires_at = now() - interval '1 minute' WHERE id = $1", p.ID)
	if _, err := e.svc.ConfirmRestore(bob.ctx, bob.now(), p.ID); !is(err, app.ErrRestoreGone) {
		t.Fatalf("confirming an expired proposal: %v", err)
	}
	if st, _ := e.svc.Status(bob.ctx); !st.Engaged || st.Pending != nil {
		t.Fatalf("after expiry: %+v", st)
	}
	p2, err := e.svc.ProposeRestore(bob.ctx, bob.now(), "now really contained")
	if err != nil {
		t.Fatalf("a proposal after expiry: %v", err)
	}
	if err := e.svc.CancelRestore(viewer.ctx, p2.ID); !denied(err) {
		t.Fatalf("a viewer canceled: %v", err)
	}
	if err := e.svc.CancelRestore(alice.ctx, p2.ID); err != nil {
		t.Fatalf("the other person canceling: %v", err)
	}
	if err := e.svc.CancelRestore(alice.ctx, p2.ID); !is(err, app.ErrRestoreGone) {
		t.Fatalf("canceling twice: %v", err)
	}
	if _, err := e.svc.ConfirmRestore(alice.ctx, alice.now(), p2.ID); !is(err, app.ErrRestoreGone) {
		t.Fatalf("confirming a canceled proposal: %v", err)
	}
	if st, _ := e.svc.Status(bob.ctx); !st.Engaged || st.Pending != nil {
		t.Fatalf("after cancel: %+v", st)
	}
	if e.audited(t, "security.kill_switch_restore_canceled", "proposal_id") != p2.ID.String() {
		t.Fatal("the cancellation is not audited")
	}
}

// TestHR113_TheKillSwitchIsReadWithContainmentRead: the state needs
// containment.read; another org's proposal is not found (T-037).
func TestHR113_TheKillSwitchIsReadWithContainmentRead(t *testing.T) {
	e := newEnv(t)
	auditor := e.person(t, "erin", td.RoleAuditor)
	viewer := e.person(t, "dan", td.RoleViewer)
	if _, err := e.svc.Status(auditor.ctx); err != nil {
		t.Fatalf("auditor: %v", err)
	}
	if _, err := e.svc.Status(viewer.ctx); !denied(err) {
		t.Fatalf("viewer: %v", err)
	}

	other := e.otherOrg(t)
	alice := other.person(t, "alice", td.RoleEmergency)
	if _, err := other.svc.Engage(alice.ctx, alice.now(), "incident"); err != nil {
		t.Fatal(err)
	}
	p, err := other.svc.ProposeRestore(alice.ctx, alice.now(), "contained")
	if err != nil {
		t.Fatal(err)
	}
	bob := e.person(t, "bob", td.RoleEmergency)
	if _, err := e.svc.ConfirmRestore(bob.ctx, bob.now(), p.ID); !is(err, app.ErrRestoreNotFound) {
		t.Fatalf("confirming another org's proposal: %v", err)
	}
	if err := e.svc.CancelRestore(bob.ctx, p.ID); !is(err, app.ErrRestoreNotFound) {
		t.Fatalf("canceling another org's proposal: %v", err)
	}
}
