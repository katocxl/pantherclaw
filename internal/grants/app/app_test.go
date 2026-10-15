// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/grants/grantstest"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

var (
	org  = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000a1")
	now  = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	team = ids.NewV7()
)

// authz grants the permissions in its set to every caller.
type authz map[tdomain.Permission]bool

func (a authz) Require(_ tapp.Caller, p tdomain.Permission, _ tdomain.Path) error {
	if a[p] {
		return nil
	}
	return tdomain.ErrPermissionDenied(p)
}

var allPerms = authz{app.PermGrantRead: true, app.PermGrantIssue: true, app.PermGrantRevoke: true, app.PermGuardrailsRead: true, app.PermGuardrailsManage: true}

type fixture struct {
	svc   *app.Service
	store *grantstest.Store
	alice domain.Principal
	agent app.Agent
	ctx   context.Context
}

func setup(t *testing.T, perms authz) *fixture {
	t.Helper()
	st := grantstest.New(org)
	f := &fixture{
		store: st, alice: domain.Principal{Kind: domain.PrincipalUser, ID: ids.NewV7()},
		agent: app.Agent{ID: ids.NewV7(), State: "VERIFIED", Path: tdomain.OrgPath(org).Child(tdomain.ScopeTeam, team), TeamID: team, EnvironmentID: ids.NewV7()},
	}
	st.AddAgent(f.agent)
	st.AddPrincipal(f.alice)
	st.AddDefinition(&defs.Definition{Operation: "payments.refund.create", Params: map[string]defs.ParamSpec{
		"amount": {Type: defs.TypeMoney, Material: true, Required: true, Currencies: []string{"USD"}},
	}})
	f.svc = &app.Service{Repo: st, Subjects: st, Defs: st, Authz: perms, Clock: clock.NewFake(now)}
	f.ctx = as(f.alice.ID, tdomain.KindUser)
	return f
}

func as(id ids.UUID, kind tdomain.PrincipalKind) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: org, Principal: tdomain.PrincipalRef{Kind: kind, ID: id}}})
}

func bounds(t *testing.T, s string) domain.Bounds {
	t.Helper()
	b, err := domain.DecodeBounds([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const refundOnly = `{"operations": ["payments.refund.create"], "params": {"payments.refund.create": {"amount": {"max": {"USD": "100"}}}}}`

func (f *fixture) issue(t *testing.T) domain.Grant {
	t.Helper()
	g, err := f.svc.Issue(f.ctx, app.IssueRequest{
		AgentID: f.agent.ID, Principal: f.alice, TaskRef: "refunds", ExpiresAt: now.Add(48 * time.Hour),
		Bounds: bounds(t, refundOnly), Delegation: domain.Delegation{Depth: 2, MaxChildren: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// run registers an active run of the agent bound to grant g (zero: none)
// with parent run parent (zero: a root run).
func (f *fixture) run(g domain.GrantID, parent ids.UUID) app.Run {
	r := app.Run{
		ID: ids.NewV7(), AgentID: f.agent.ID, InstanceID: ids.NewV7(), Principal: f.alice,
		EnvironmentID: f.agent.EnvironmentID, ParentRunID: parent, GrantID: g, Active: true, ExpiresAt: now.Add(8 * time.Hour),
	}
	f.store.AddRun(r)
	return r
}

func (f *fixture) delegate(t *testing.T, parentRun app.Run, b string) (domain.Grant, app.Run, error) {
	return f.delegateDepth(t, parentRun, b, 0)
}

func (f *fixture) delegateDepth(t *testing.T, parentRun app.Run, b string, depth int) (domain.Grant, app.Run, error) {
	t.Helper()
	child := f.run(domain.GrantID{}, parentRun.ID)
	g, err := f.svc.Delegate(context.Background(), app.Workload{Org: org, InstanceID: parentRun.InstanceID, RunID: parentRun.ID},
		app.DelegateRequest{ChildRunID: child.ID, Bounds: bounds(t, b), Delegation: domain.Delegation{Depth: depth, MaxChildren: min(depth, 1)}})
	return g, child, err
}

func reason(err error) string { return pcerr.ReasonOf(err) }

func TestIssueChecksPermissionAgentAndPrincipal(t *testing.T) {
	f := setup(t, allPerms)
	g := f.issue(t)
	if g.Grantor != f.alice || g.EnvironmentID != f.agent.EnvironmentID || g.Revision != 1 {
		t.Fatalf("issued %+v", g)
	}
	if evs := f.store.Events(); len(evs) != 1 || evs[0].Name != "grant.issued" {
		t.Fatalf("audit events %+v", evs)
	}

	denied := setup(t, authz{})
	if _, err := denied.svc.Issue(denied.ctx, app.IssueRequest{AgentID: denied.agent.ID, Principal: denied.alice, ExpiresAt: now.Add(time.Hour)}); reason(err) != "PERMISSION_DENIED" {
		t.Fatalf("issued without grant.issue: %v", err)
	}

	f.store.AddAgent(app.Agent{ID: ids.NewV7(), State: "SUSPENDED", Path: f.agent.Path, EnvironmentID: f.agent.EnvironmentID})
	for _, req := range []app.IssueRequest{
		{AgentID: ids.NewV7(), Principal: f.alice, ExpiresAt: now.Add(time.Hour)},
		{AgentID: f.agent.ID, Principal: domain.Principal{Kind: domain.PrincipalUser, ID: ids.NewV7()}, ExpiresAt: now.Add(time.Hour)},
		{AgentID: f.agent.ID, Principal: f.alice, ExpiresAt: now.Add(30 * 24 * time.Hour)},
	} {
		if _, err := f.svc.Issue(f.ctx, req); err == nil {
			t.Fatalf("issued %+v", req)
		}
	}
}

func TestHR161_OnlyPeopleIssueReviseOrChangeGuardrails(t *testing.T) {
	f := setup(t, allPerms)
	g := f.issue(t)
	sa := as(ids.NewV7(), tdomain.KindServiceAccount)
	if _, err := f.svc.Issue(sa, app.IssueRequest{AgentID: f.agent.ID, Principal: f.alice, ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, app.ErrHumanOnly) {
		t.Fatalf("a service account issued a grant: %v", err)
	}
	if _, _, err := f.svc.Revise(sa, app.ReviseRequest{ID: g.ID, Revision: 1, Bounds: g.Bounds}); !errors.Is(err, app.ErrHumanOnly) {
		t.Fatalf("a service account revised a grant: %v", err)
	}
	if _, _, err := f.svc.PutEnvelope(sa, app.EnvelopeRequest{Scope: domain.Scope{Kind: domain.ScopeOrg}, Name: "org"}); !errors.Is(err, app.ErrHumanOnly) {
		t.Fatalf("a service account changed guardrails: %v", err)
	}
	if _, err := f.svc.Issue(context.Background(), app.IssueRequest{}); !errors.Is(err, tapp.ErrNoCaller) {
		t.Fatalf("issued without a caller: %v", err)
	}
	// A workload can only narrow its run's grant, never widen it.
	parentRun := f.run(g.ID, ids.UUID{})
	if _, _, err := f.delegate(t, parentRun, `{"operations": ["payments.*"]}`); reason(err) != "OUTSIDE_ALLOWED_AUTHORITY" {
		t.Fatalf("a workload delegated more than its grant: %v", err)
	}
	child, childRun, err := f.delegate(t, parentRun, `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "20"}}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if child.Grantor.Kind != domain.PrincipalInstance || child.Grantor.ID != parentRun.InstanceID || child.Principal != f.alice {
		t.Fatalf("delegated grant provenance %+v", child)
	}
	if f.store.RunOf(childRun.ID).GrantID != child.ID {
		t.Fatal("the delegated grant was not bound to the child run")
	}
}

func TestHR047_RevocationCascadesInOneStep(t *testing.T) {
	f := setup(t, allPerms)
	root := f.issue(t)
	r0 := f.run(root.ID, ids.UUID{})
	c1, run1, err := f.delegateDepth(t, r0, `{}`, 1)
	if err != nil {
		t.Fatal(err)
	}
	run1.GrantID = c1.ID
	c2, _, err := f.delegate(t, run1, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	epoch := f.store.Epoch()
	revoked, err := f.svc.Revoke(f.ctx, root.ID, "task finished")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 3 {
		t.Fatalf("revoked %v, want the root, child and grandchild", revoked)
	}
	for _, id := range []domain.GrantID{root.ID, c1.ID, c2.ID} {
		if g, _ := f.store.Grant(context.Background(), org, id); g.State != domain.StateRevoked {
			t.Fatalf("%s is %s after the cascade", id, g.State)
		}
	}
	if f.store.Epoch() != epoch+1 {
		t.Fatal("revocation did not increment the containment epoch")
	}
	if _, _, err := f.delegate(t, r0, `{}`); err == nil {
		t.Fatal("delegated from a revoked grant")
	}
}

// TestGrantsIssuedForNowTolerateAClockBehind: a grant issued to take
// effect now, and a grant delegated from it, start IssueSkew before the
// issuer's clock, so a database clock slightly behind it finds them valid
// at once; they still expire when asked, and a delegated grant never
// starts before its parent.
func TestGrantsIssuedForNowTolerateAClockBehind(t *testing.T) {
	f := setup(t, allPerms)
	root := f.issue(t)
	if !root.NotBefore.Equal(now.Add(-domain.IssueSkew)) || !root.ExpiresAt.Equal(now.Add(48*time.Hour)) {
		t.Fatalf("root %s .. %s", root.NotBefore, root.ExpiresAt)
	}
	if _, ok := root.Usable(now.Add(-time.Second)); !ok {
		t.Fatal("a clock a second behind finds the grant not yet valid")
	}
	child, _, err := f.delegate(t, f.run(root.ID, ids.UUID{}), `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if !child.NotBefore.Equal(root.NotBefore) {
		t.Fatalf("child starts %s, parent %s", child.NotBefore, root.NotBefore)
	}
}

func TestHR047_ConcurrentDelegationsRespectFanOut(t *testing.T) {
	f := setup(t, allPerms)
	root := f.issue(t) // MaxChildren 3
	parentRun := f.run(root.ID, ids.UUID{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 20 {
		wg.Go(func() {
			if _, _, err := f.delegate(t, parentRun, `{}`); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 3 {
		t.Fatalf("%d delegations succeeded, want exactly the fan-out of 3", ok)
	}
}

func TestDelegationNeedsTheRunsOwnInstanceAndAChildRun(t *testing.T) {
	f := setup(t, allPerms)
	root := f.issue(t)
	parentRun := f.run(root.ID, ids.UUID{})
	stranger := f.run(domain.GrantID{}, ids.UUID{}) // not a child of parentRun
	w := app.Workload{Org: org, InstanceID: parentRun.InstanceID, RunID: parentRun.ID}
	if _, err := f.svc.Delegate(context.Background(), w, app.DelegateRequest{ChildRunID: stranger.ID}); !errors.Is(err, app.ErrRunNotEligible) {
		t.Fatalf("delegated to a run that is not a child: %v", err)
	}
	child := f.run(domain.GrantID{}, parentRun.ID)
	w.InstanceID = ids.NewV7()
	if _, err := f.svc.Delegate(context.Background(), w, app.DelegateRequest{ChildRunID: child.ID}); !errors.Is(err, app.ErrRunNotEligible) {
		t.Fatalf("another instance delegated the run's grant: %v", err)
	}
	w.Org = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000b2")
	if _, err := f.svc.Delegate(context.Background(), w, app.DelegateRequest{ChildRunID: child.ID}); !errors.Is(err, app.ErrRunNotFound) {
		t.Fatalf("another org's run was found: %v", err)
	}
}

func TestReviseNarrowsAtOnceAndReportsWidening(t *testing.T) {
	f := setup(t, allPerms)
	g := f.issue(t)
	epoch := f.store.Epoch()
	next, rev, err := f.svc.Revise(f.ctx, app.ReviseRequest{
		ID: g.ID, Revision: 1, Bounds: bounds(t, `{"operations": ["payments.refund.create"], "params": {"payments.refund.create": {"amount": {"max": {"USD": "50"}}}}}`),
		Delegation: g.Delegation,
	})
	if err != nil || rev.Widens || next.Revision != 2 || f.store.Epoch() != epoch+1 {
		t.Fatalf("narrowing: %+v %+v %v epoch %d", next, rev, err, f.store.Epoch())
	}
	if _, _, err := f.svc.Revise(f.ctx, app.ReviseRequest{ID: g.ID, Revision: 1, Bounds: g.Bounds}); !errors.Is(err, app.ErrRevisionChanged) {
		t.Fatalf("a stale revision was applied: %v", err)
	}
	_, rev, err = f.svc.Revise(f.ctx, app.ReviseRequest{ID: g.ID, Revision: 2, Bounds: g.Bounds, Delegation: g.Delegation, ExpiresAt: now.Add(72 * time.Hour)})
	if err != nil || !rev.Widens {
		t.Fatalf("widening: %+v %v", rev, err)
	}
}

func TestRevokeByIssuerOrPermission(t *testing.T) {
	f := setup(t, authz{app.PermGrantIssue: true})
	g := f.issue(t)
	bob := as(ids.NewV7(), tdomain.KindUser)
	if _, err := f.svc.Revoke(bob, g.ID, "no"); reason(err) != "PERMISSION_DENIED" {
		t.Fatalf("someone else revoked without grant.revoke: %v", err)
	}
	if _, err := f.svc.Revoke(f.ctx, g.ID, "bad"+string(rune(0x202e))); reason(err) != "REASON_INVALID" {
		t.Fatalf("a bidi reason was accepted: %v", err)
	}
	if _, err := f.svc.Revoke(f.ctx, g.ID, "done"); err != nil {
		t.Fatalf("the issuer revokes their own grant: %v", err)
	}
}

func TestGuardrailsApplyAndReportWidening(t *testing.T) {
	f := setup(t, allPerms)
	org0 := domain.Scope{Kind: domain.ScopeOrg}
	e, ch, err := f.svc.PutEnvelope(f.ctx, app.EnvelopeRequest{Scope: org0, Name: "org", Bounds: bounds(t, `{"operations": ["payments.*"]}`)})
	if err != nil || ch.Widens || e.Revision != 1 {
		t.Fatalf("first guardrail: %+v %+v %v", e, ch, err)
	}
	if _, _, err := f.svc.PutEnvelope(f.ctx, app.EnvelopeRequest{Scope: org0, Name: "org"}); !errors.Is(err, app.ErrRevisionChanged) {
		t.Fatalf("a stale revision was applied: %v", err)
	}
	_, ch, err = f.svc.PutEnvelope(f.ctx, app.EnvelopeRequest{Scope: org0, Revision: 1, Name: "org"})
	if err != nil || !ch.Widens {
		t.Fatalf("removing a bound widens: %+v %v", ch, err)
	}
	// A grant outside the guardrail is refused.
	if _, _, err := f.svc.PutEnvelope(f.ctx, app.EnvelopeRequest{Scope: org0, Revision: 2, Name: "org", Bounds: bounds(t, `{"operations": ["crm.*"]}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Issue(f.ctx, app.IssueRequest{AgentID: f.agent.ID, Principal: f.alice, ExpiresAt: now.Add(time.Hour), Bounds: bounds(t, refundOnly)}); reason(err) != "OUTSIDE_ALLOWED_AUTHORITY" {
		t.Fatalf("a grant outside the guardrail: %v", err)
	}
}

func TestCheckRunGrant(t *testing.T) {
	f := setup(t, allPerms)
	g := f.issue(t)
	bind := app.RunBinding{AgentID: f.agent.ID, Principal: f.alice, EnvironmentID: f.agent.EnvironmentID}
	if exp, err := f.svc.CheckRunGrant(context.Background(), org, g.ID, bind); err != nil || !exp.Equal(g.ExpiresAt) {
		t.Fatalf("CheckRunGrant = %v, %v", exp, err)
	}
	for _, b := range []app.RunBinding{
		{AgentID: ids.NewV7(), Principal: f.alice, EnvironmentID: f.agent.EnvironmentID},
		{AgentID: f.agent.ID, Principal: domain.Principal{Kind: domain.PrincipalUser, ID: ids.NewV7()}, EnvironmentID: f.agent.EnvironmentID},
		{AgentID: f.agent.ID, Principal: f.alice, EnvironmentID: ids.NewV7()},
	} {
		if _, err := f.svc.CheckRunGrant(context.Background(), org, g.ID, b); reason(err) != domain.ReasonGrantMismatch {
			t.Fatalf("bound to %+v: %v", b, err)
		}
	}
	parentRun := f.run(g.ID, ids.UUID{})
	child, _, err := f.delegate(t, parentRun, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CheckRunGrant(context.Background(), org, child.ID, bind); reason(err) != domain.ReasonGrantMismatch {
		t.Fatalf("a delegated grant was bound at StartRun: %v", err)
	}
}

func TestGetShowsLineageAndEffectiveAuthority(t *testing.T) {
	f := setup(t, allPerms)
	root := f.issue(t)
	parentRun := f.run(root.ID, ids.UUID{})
	child, _, err := f.delegate(t, parentRun, `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "20"}}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.svc.Get(f.ctx, child.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Lineage) != 2 || v.Lineage[0].ID != root.ID || v.Grant.ID != child.ID {
		t.Fatalf("lineage %+v", v.Lineage)
	}
	if got := v.Effective.Params["payments.refund.create"]["amount"].Max["USD"]; got != "20" {
		t.Fatalf("effective maximum %q, want 20", got)
	}
	if _, err := f.svc.Get(f.ctx, domain.NewGrantID()); !errors.Is(err, app.ErrGrantNotFound) {
		t.Fatalf("Get(unknown) = %v", err)
	}
}

type refusals struct{ events []audit.Event }

func (r *refusals) RecordRefusal(_ context.Context, _ ids.OrgID, ev audit.Event) error {
	r.events = append(r.events, ev)
	return nil
}

// TestHR161_RefusedGrantChangesAreAudited: a non-human caller's refused
// issue or revision, and a workload's delegation beyond its grant, are
// audited with the caller as actor, so pc.authority.self_issue sees them
// (G0 M10 D59 H1).
func TestHR161_RefusedGrantChangesAreAudited(t *testing.T) {
	f := setup(t, allPerms)
	rec := &refusals{}
	f.svc.Refusals = rec
	g := f.issue(t)
	saID := ids.NewV7()
	sa := as(saID, tdomain.KindServiceAccount)
	if _, err := f.svc.Issue(sa, app.IssueRequest{AgentID: f.agent.ID, Principal: f.alice, ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, app.ErrHumanOnly) {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Revise(sa, app.ReviseRequest{ID: g.ID, Revision: 1, Bounds: g.Bounds}); !errors.Is(err, app.ErrHumanOnly) {
		t.Fatal(err)
	}
	parentRun := f.run(g.ID, ids.UUID{})
	if _, _, err := f.delegate(t, parentRun, `{"operations": ["payments.*"]}`); err == nil {
		t.Fatal("widening delegation accepted")
	}
	if len(rec.events) != 3 {
		t.Fatalf("refusals %d, want 3", len(rec.events))
	}
	for i, want := range []string{"grant.issue_refused", "grant.issue_refused", "grant.delegate_refused"} {
		ev := rec.events[i]
		if ev.Name != want || ev.Outcome != audit.Denied {
			t.Errorf("refusal %d: %s %s", i, ev.Name, ev.Outcome)
		}
	}
	if rec.events[0].Actor.ID != saID.String() || rec.events[0].Details["agent"] != f.agent.ID.String() {
		t.Errorf("issue refusal: %+v", rec.events[0])
	}
}
