// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The core-A review amendments (D64–D69, D74, D84): enabling never
// un-pauses, ChangeService permissions, owner changes, the Closed
// callback, revocation scope, narrowing-only launch limits and previews.

// validated creates an automation and a validated version of it.
func (e *env) validated(name string) (autoapp.Automation, autoapp.Version) {
	e.t.Helper()
	a, err := e.svc.CreateAutomation(e.alice.cli, name, "Refund small tickets.", autodomain.WorkAgent, e.alice.id)
	if err != nil {
		e.t.Fatal(err)
	}
	v, err := e.svc.CreateDraftVersion(e.alice.cli, a.ID, []byte(e.definition(5)))
	if err != nil {
		e.t.Fatal(err)
	}
	if v, ok, err := e.svc.ValidateVersion(e.alice.cli, v.ID); err != nil || !ok {
		e.t.Fatalf("validate: %v %+v", err, v.Findings)
	}
	return a, v
}

func (e *env) decidedReason(id ids.UUID) string {
	e.t.Helper()
	var s *string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT decided_reason FROM pc.change_requests WHERE org_id = $1 AND id = $2", e.org, id).Scan(&s)
	}); err != nil || s == nil {
		return ""
	}
	return *s
}

func (e *env) requestState(id ids.UUID) string {
	e.t.Helper()
	var s string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state FROM pc.change_requests WHERE org_id = $1 AND id = $2", e.org, id).Scan(&s)
	}); err != nil {
		e.t.Fatal(err)
	}
	return s
}

// TestD64_EnablingNeverUnpauses: a new version enabled while the
// automation is paused leaves it paused; only Resume ends a pause.
func TestD64_EnablingNeverUnpauses(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	if _, _, err := e.svc.PauseAutomation(e.alice.cli, a.ID, false, "hold"); err != nil {
		t.Fatal(err)
	}
	v2, err := e.svc.CreateDraftVersion(e.alice.cli, a.ID, []byte(e.definition(7)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := e.svc.ValidateVersion(e.alice.cli, v2.ID); err != nil || !ok {
		t.Fatalf("validate: %v", err)
	}
	en, err := e.svc.RequestEnable(e.alice.cli, v2.ID, autodomain.RolloutShadow, nil, ids.UUID{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Changes.Confirm(e.bob.page, en.Request.ID, e.sign(e.bob, en.Request)); err != nil {
		t.Fatalf("%v (%s)", err, e.decidedReason(en.Request.ID))
	}
	got, err := e.svc.GetAutomation(e.alice.cli, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != autodomain.StatePaused || got.EnabledVersion != v2.ID || got.PauseReason != autodomain.PauseUser {
		t.Errorf("after enabling a new version: state %s version %s reason %s", got.State, got.EnabledVersion, got.PauseReason)
	}
}

// closedLog records Closed callbacks (D74).
type closedLog struct{ states []string }

func (l *closedLog) handler(perm td.Permission) changes.Handler {
	return changes.Handler{
		Permission: perm, DeclinePermissions: []td.Permission{perm},
		Required: func(context.Context, db.TenantTx, changes.Request) (int, error) { return 1, nil },
		Eligible: func(context.Context, db.TenantTx, changes.Request, ids.UUID) (bool, string, error) {
			return true, "", nil
		},
		Apply: func(context.Context, db.TenantTx, changes.Request, []ids.UUID) error { return nil },
		Closed: func(_ context.Context, _ db.TenantTx, r changes.Request, state string) error {
			l.states = append(l.states, r.Kind+":"+state)
			return nil
		},
	}
}

func (e *env) request(p person, domain, kind string) changes.Request {
	e.t.Helper()
	r, err := e.svc.Changes.Request(p.cli, changes.Requested{
		Domain: domain, Kind: kind, Subject: ids.NewV7(), Content: sha256.Sum256([]byte(kind)), Summary: map[string]string{"kind": kind},
	})
	if err != nil {
		e.t.Fatalf("request %s/%s: %v", domain, kind, err)
	}
	return r
}

// TestD66_ChangeServicePermissions: each domain's requests are visible to
// the domain's permission holders and their requester only, and only they
// may decline them, never a service account.
func TestD66_ChangeServicePermissions(t *testing.T) {
	e := newEnv(t)
	log := &closedLog{}
	e.svc.Changes.Register(changes.DomainProtected, "TEST_CHANGE", log.handler(td.PermProtectedChangeManage))
	e.svc.Changes.Register(changes.DomainPublisher, "TEST_CLEAR", log.handler(td.PermPublisherCompromise))
	dave := e.person("dave", td.RoleViewer)
	eve := e.person("eve", td.RoleSecurityAdmin)

	_, v := e.validated("refunds")
	en, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutShadow, nil, ids.UUID{})
	if err != nil {
		t.Fatal(err)
	}
	protected := e.request(e.alice, changes.DomainProtected, "TEST_CHANGE")
	publisher := e.request(eve, changes.DomainPublisher, "TEST_CLEAR")

	for _, tc := range []struct {
		who  string
		p    person
		r    changes.Request
		sees bool
	}{
		{"viewer, automation", dave, en.Request, true},
		{"viewer, protected", dave, protected, false},
		{"viewer, publisher", dave, publisher, false},
		{"requester, protected", e.alice, protected, true},
		{"org admin, publisher", e.alice, publisher, false},
		{"security admin, protected", eve, protected, true},
		{"security admin, publisher", eve, publisher, true},
	} {
		_, err := e.svc.Changes.Get(tc.p.cli, tc.r.ID)
		if got := err == nil; got != tc.sees {
			t.Errorf("%s: Get %v, want visible %v", tc.who, err, tc.sees)
		}
		list, _, err := e.svc.Changes.List(tc.p.cli, changes.Filter{Limit: 200})
		if err != nil {
			t.Fatal(err)
		}
		listed := false
		for _, x := range list {
			listed = listed || x.ID == tc.r.ID
		}
		if listed != tc.sees {
			t.Errorf("%s: listed %v, want %v", tc.who, listed, tc.sees)
		}
	}
	// Declining needs the domain's decline permission or being the
	// requester, and a person.
	if _, err := e.svc.Changes.Decline(dave.cli, en.Request.ID, "no"); reason(err) != "DECLINE_DENIED" {
		t.Errorf("viewer declines an enabling: %v", err)
	}
	sa := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org:       e.org,
		Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings:  []td.Binding{{Role: td.RoleAutomationPublisher, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}})
	if _, err := e.svc.Changes.Decline(sa, en.Request.ID, "no"); reason(err) != "HUMAN_ONLY" {
		t.Errorf("a service account declines: %v", err)
	}
	if _, err := e.svc.Changes.Decline(e.bob.cli, en.Request.ID, "not now"); err != nil {
		t.Errorf("a publisher declines an enabling: %v", err)
	}
	if _, err := e.svc.Changes.Decline(e.alice.cli, protected.ID, "withdrawn"); err != nil {
		t.Errorf("the requester declines: %v", err)
	}
	if _, err := e.svc.Changes.Decline(e.alice.cli, publisher.ID, "no"); reason(err) != "CHANGE_NOT_FOUND" {
		t.Errorf("org admin declines a publisher request: %v", err)
	}
	// D74: Closed runs for a declined and a voided request.
	voider, err := tapp.CallerFrom(eve.cli)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.pool.InTenantTx(eve.cli, e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := e.svc.Changes.Void(ctx, tx, voider, changes.DomainPublisher, publisher.Subject, "TEST")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"TEST_CHANGE:DECLINED", "TEST_CLEAR:VOIDED"}; len(log.states) != 2 || log.states[0] != want[0] || log.states[1] != want[1] {
		t.Errorf("closed callbacks %v, want %v", log.states, want)
	}
}

// TestD74_ExpiryWindowPerKind: a request lives at most 24 hours, except a
// protected EMERGENCY_REVIEW (72).
func TestD74_ExpiryWindowPerKind(t *testing.T) {
	e := newEnv(t)
	insert := func(domain, kind, ttl string) error {
		return e.execErr(`INSERT INTO pc.change_requests (org_id, id, domain, kind, subject_id, content_digest, binding, summary,
			required, requested_by, expires_at) VALUES ($1, gen_random_uuid(), $2, $3, gen_random_uuid(), decode(repeat('ab', 32), 'hex'),
			sha256(gen_random_uuid()::text::bytea), '{}', 1, 'user:x', now() + $4::interval)`, e.org, domain, kind, ttl)
	}
	if err := insert("protected", "EMERGENCY_REVIEW", "71 hours"); err != nil {
		t.Errorf("a 71-hour emergency review: %v", err)
	}
	for _, c := range [][3]string{{"protected", "EMERGENCY_REVIEW", "73 hours"}, {"protected", "SETTINGS", "25 hours"}, {"automation", "ENABLE", "25 hours"}} {
		if err := insert(c[0], c[1], c[2]); err == nil {
			t.Errorf("%s/%s for %s accepted", c[0], c[1], c[2])
		}
	}
}

// TestD68_OwnerChangeVoidsPendingEnabling: the owner lives on the row; a
// new owner voids the pending enabling, and must be an active person.
func TestD68_OwnerChangeVoidsPendingEnabling(t *testing.T) {
	e := newEnv(t)
	a, v := e.validated("refunds")
	en, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutShadow, nil, ids.UUID{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetOwner(e.alice.cli, a.ID, ids.NewV7()); reason(err) != "OWNER_NOT_ACTIVE_PERSON" {
		t.Errorf("unknown owner: %v", err)
	}
	if _, err := e.svc.SetOwner(e.bob.cli, a.ID, e.bob.id); reason(err) == "" {
		t.Error("a publisher without automation.manage changed the owner")
	}
	got, err := e.svc.SetOwner(e.alice.cli, a.ID, e.cat.id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != e.cat.id {
		t.Errorf("owner %s", got.Owner)
	}
	if s := e.requestState(en.Request.ID); s != changes.StateVoided {
		t.Errorf("pending enabling after an owner change: %s", s)
	}
	if n := e.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.automation.owner_changed'`, e.org); n != 1 {
		t.Errorf("owner change records %d", n)
	}
}

// TestD65_RevocationStaysInsideRevocable: TRIGGER_GRANT and CEILING_AGENTS
// revoke only the grants of authority.revocable's agents (E10).
func TestD65_RevocationStaysInsideRevocable(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutFull, 5)
	g, err := e.issue(a, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	revoke := func(scope string, mod func(*grantsapp.AutomationRevoke)) ([]gdomain.GrantID, error) {
		in := grantsapp.AutomationRevoke{
			Org: e.org, Automation: a.ID, Execution: ids.NewV7(), Ceiling: a.Ceiling.ID, ServiceAccount: a.ServiceAccount,
			Agents: []ids.UUID{e.agent}, Grant: g.ID.UUID(), Scope: scope, Reason: "test",
		}
		mod(&in)
		var out []gdomain.GrantID
		err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			out, err = e.grants.RevokeForAutomationTx(ctx, tx, in)
			return err
		})
		return out, err
	}
	for name, mod := range map[string]func(*grantsapp.AutomationRevoke){
		"none declared": func(*grantsapp.AutomationRevoke) {},
		"another agent": func(in *grantsapp.AutomationRevoke) { in.Revocable = []ids.UUID{e.other} },
		"agents, outside": func(in *grantsapp.AutomationRevoke) {
			in.Scope, in.Revocable = grantsapp.RevokeScopeCeilingAgents, []ids.UUID{e.other}
		},
	} {
		if _, err := revoke(grantsapp.RevokeScopeTriggerGrant, mod); reason(err) != "OUTSIDE_CEILING" {
			t.Errorf("%s: %v, want OUTSIDE_CEILING", name, err)
		}
	}
	out, err := revoke(grantsapp.RevokeScopeTriggerGrant, func(in *grantsapp.AutomationRevoke) { in.Revocable = []ids.UUID{e.agent} })
	if err != nil || len(out) != 1 {
		t.Errorf("revocable agent: %v %v", out, err)
	}
}

// TestD84_LaunchLimitsNarrowAndPreviewsEvaluate: a launch only lowers the
// per-grant limits, a spending operation needs a per-grant budget, and a
// SHADOW or TEST preview runs every check without writing.
func TestD84_LaunchLimitsNarrowAndPreviewsEvaluate(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutFull, 5)
	extra := gdomain.Limits{Budgets: []gdomain.BudgetRule{{
		ID: "extra", Grouping: "task", Operations: gdomain.Ops{"payments.refund.create"}, Currency: "USD", Limit: "10.00", Period: "grant",
	}}}
	if _, err := e.issue(a, v, func(in *grantsapp.AutomationIssue) { in.Limits = extra }); reason(err) != "OUTSIDE_CEILING" {
		t.Errorf("a budget the ceiling lacks: %v", err)
	}
	spending["payments.refund.create"] = true
	t.Cleanup(func() { delete(spending, "payments.refund.create") })
	if _, err := e.issue(a, v, nil); reason(err) != "OUTSIDE_CEILING" {
		t.Errorf("a spending operation without a per-grant budget: %v", err)
	}
	delete(spending, "payments.refund.create")

	// SHADOW: no live issuance, but a dry run evaluates.
	sa, sv := e.enabled("shadowed", autodomain.RolloutShadow, 5)
	if _, err := e.issue(sa, sv, func(in *grantsapp.AutomationIssue) { in.Live = false }); reason(err) != "CEILING_INACTIVE" {
		t.Errorf("a shadow execution issues: %v", err)
	}
	if _, err := e.issue(sa, sv, func(in *grantsapp.AutomationIssue) { in.Live, in.DryRun = false, true }); err != nil {
		t.Errorf("shadow preview: %v", err)
	}
	if _, err := e.issue(sa, sv, func(in *grantsapp.AutomationIssue) { in.Live = true }); reason(err) != "CEILING_INACTIVE" {
		t.Errorf("a live grant under a SHADOW rollout: %v", err)
	}
	// TEST of a version never enabled: checked against its declared ceiling.
	ta, tv := e.validated("tested")
	ta, err := e.svc.GetAutomation(e.alice.cli, ta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.issue(ta, tv, func(in *grantsapp.AutomationIssue) { in.Live, in.DryRun = false, true }); err != nil {
		t.Errorf("test preview: %v", err)
	}
	if _, err := e.issue(ta, tv, func(in *grantsapp.AutomationIssue) {
		in.Live, in.DryRun, in.AgentID = false, true, e.other
	}); reason(err) != "OUTSIDE_CEILING" {
		t.Errorf("test preview outside the ceiling: %v", err)
	}
	if n := e.count("SELECT count(*) FROM pc.grants WHERE org_id = $1 AND ceiling_id IS NOT NULL AND agent_id = $2", e.org, e.agent); n != 0 {
		t.Errorf("%d grants written", n)
	}
}

// TestD69_PublishedVersionFrozen (C12): once a version leaves authoring
// every column is frozen; only its state moves on.
func TestD69_PublishedVersionFrozen(t *testing.T) {
	e := newEnv(t)
	_, v := e.enabled("refunds", autodomain.RolloutShadow, 5)
	for name, sql := range map[string]string{
		"summary":    "UPDATE pc.automation_versions SET summary = 'x' WHERE org_id = $1 AND id = $2",
		"tested_at":  "UPDATE pc.automation_versions SET tested_at = now() WHERE org_id = $1 AND id = $2",
		"tested_run": "UPDATE pc.automation_versions SET tested_run_id = gen_random_uuid() WHERE org_id = $1 AND id = $2",
		"validated":  "UPDATE pc.automation_versions SET validated_at = now() WHERE org_id = $1 AND id = $2",
	} {
		if err := e.execErr(sql, e.org, v.ID); err == nil {
			t.Errorf("%s of a published version changed", name)
		}
	}
	if err := e.execErr("UPDATE pc.automation_versions SET state = 'SUPERSEDED' WHERE org_id = $1 AND id = $2", e.org, v.ID); err != nil {
		t.Errorf("PUBLISHED → SUPERSEDED: %v", err)
	}
	if _, err := e.svc.CreateAutomation(e.alice.cli, "ends-", "x", autodomain.WorkAgent, e.alice.id); reason(err) == "" {
		t.Error("a name ending in a hyphen was accepted")
	}
}

// subjectChangedError is a domain's own void error (protect's SUBJECT_CHANGED).
type subjectChangedError struct{}

func (subjectChangedError) Error() string      { return "subject changed" }
func (subjectChangedError) VoidReason() string { return "SUBJECT_CHANGED" }

// TestD88_ApplyVoidVoidsInTheConfirmingTransaction: an Apply error with a
// void reason voids the request in the confirming transaction; what Apply
// wrote is rolled back and the confirmation stays recorded.
func TestD88_ApplyVoidVoidsInTheConfirmingTransaction(t *testing.T) {
	e := newEnv(t)
	log := &closedLog{}
	h := log.handler(td.PermProtectedChangeManage)
	h.Apply = func(ctx context.Context, tx db.TenantTx, r changes.Request, _ []ids.UUID) error {
		if _, err := tx.Exec(ctx, "UPDATE pc.orgs SET name = 'changed' WHERE id = $1", e.org); err != nil {
			return err
		}
		return subjectChangedError{}
	}
	e.svc.Changes.Register(changes.DomainProtected, "TEST_CHANGE", h)
	eve := e.person("eve", td.RoleSecurityAdmin)
	r := e.request(eve, changes.DomainProtected, "TEST_CHANGE")
	if _, err := e.svc.Changes.Confirm(eve.page, r.ID, e.sign(eve, r)); !errors.Is(err, changes.ErrVoided) {
		t.Fatalf("confirm: %v, want ErrVoided", err)
	}
	if s, why := e.requestState(r.ID), e.decidedReason(r.ID); s != changes.StateVoided || why != "SUBJECT_CHANGED" {
		t.Errorf("request %s (%s)", s, why)
	}
	if n := e.count("SELECT count(*) FROM pc.orgs WHERE id = $1 AND name = 'changed'", e.org); n != 0 {
		t.Error("Apply's writes were kept")
	}
	if n := e.count("SELECT count(*) FROM pc.change_confirmations WHERE org_id = $1 AND request_id = $2", e.org, r.ID); n != 1 {
		t.Errorf("confirmations %d", n)
	}
	if len(log.states) != 1 || log.states[0] != "TEST_CHANGE:VOIDED" {
		t.Errorf("closed callbacks %v", log.states)
	}
}
