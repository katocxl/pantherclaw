// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

// t008Tree is one admitted instance of a verified agent acting in a tree of
// runs: a root run bound to a grant a person issued, and the child runs it
// starts (M3 StartChildRun) and delegates part of its grant to (the grants
// Delegate use case). Every action goes through the Authority with the
// workload's own token and proof.
type t008Tree struct {
	f      fixture
	agent  ids.UUID
	wl     workload
	grants *grantsapp.Service
}

// t008NewTree runs the grant use cases on clk, against the fixture's
// database; the Authority always decides on the database clock.
func t008NewTree(t *testing.T, clk clock.Clock) t008Tree {
	t.Helper()
	f := setup(t, "1000", 0, time.Minute)
	agent := f.agent(t)
	gs := &grantspg.Store{Pool: f.pool}
	return t008Tree{
		f: f, agent: agent, wl: f.admitted(t, agent),
		grants: &grantsapp.Service{Repo: gs, Subjects: gs, Defs: &defspg.Store{Pool: f.pool}, Authz: allow{}, Clock: clk},
	}
}

// t008Terms are the terms of a root grant, as API JSON; empty limits or
// requirements leave them out.
type t008Terms struct {
	bounds, limits, requirements string
	delegation                   gdomain.Delegation
	lifetime                     time.Duration
}

// t008Refunds allows refunds of charges (ch_…) of at most 100 USD each.
const t008Refunds = `{"operations": ["payments.refund.create"], "targets": {"payments.charge": {"prefixes": ["ch_"]}},
  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`

func t008Bounds(t *testing.T, raw string) gdomain.Bounds {
	t.Helper()
	b, err := gdomain.DecodeBounds([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// issue has the agent's owner issue a root grant with the terms.
func (tr t008Tree) issue(t *testing.T, terms t008Terms) gdomain.Grant {
	t.Helper()
	req := grantsapp.IssueRequest{
		AgentID: tr.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: tr.f.owner}, TaskRef: "refunds",
		ExpiresAt: tr.grants.Clock.Now().Add(terms.lifetime), Bounds: t008Bounds(t, terms.bounds), Delegation: terms.delegation,
	}
	var err error
	if terms.limits != "" {
		if req.Limits, err = gdomain.DecodeLimits([]byte(terms.limits)); err != nil {
			t.Fatal(err)
		}
	}
	if req.Requirements, err = gdomain.DecodeRequirements([]byte(terms.requirements)); err != nil {
		t.Fatal(err)
	}
	g, err := tr.grants.Issue(tr.f.ownerCtx(), req)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// start starts a root run of the instance bound to grant g.
func (tr t008Tree) start(t *testing.T, g gdomain.GrantID) ids.UUID {
	t.Helper()
	id, inst := g.UUID(), tr.wl.inst.Instance
	r, err := tr.f.runs.StartRun(tr.f.ownerCtx(), runsapp.StartInput{AgentID: tr.agent, InstanceID: &inst, GrantID: &id})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

// delegate starts a child run of parent, as the instance acting in parent,
// and asks to delegate req to it. It returns the child run whether or not
// the delegation was accepted.
func (tr t008Tree) delegate(t *testing.T, parent ids.UUID, req grantsapp.DelegateRequest) (ids.UUID, gdomain.Grant, error) {
	t.Helper()
	inst := tr.wl.inst.Instance
	child, err := tr.f.runs.StartChildRun(context.Background(), runsapp.ChildInput{
		Caller: tr.wl.inst, ParentRunID: parent, AgentID: tr.agent, InstanceID: &inst,
	})
	if err != nil {
		t.Fatal(err)
	}
	req.ChildRunID = child.ID
	g, err := tr.grants.Delegate(context.Background(), grantsapp.Workload{Org: tr.f.gw.Org, InstanceID: inst, RunID: parent}, req)
	return child.ID, g, err
}

// mustDelegate is delegate for a delegation that must be accepted.
func (tr t008Tree) mustDelegate(t *testing.T, parent ids.UUID, req grantsapp.DelegateRequest) (ids.UUID, gdomain.Grant) {
	t.Helper()
	run, g, err := tr.delegate(t, parent, req)
	if err != nil {
		t.Fatalf("delegation refused: %v", err)
	}
	return run, g
}

// refund asks the Authority for a refund of amount USD on a new refundable
// charge, in run, with the instance's verified credentials.
func (tr t008Tree) refund(t *testing.T, run ids.UUID, amount string) authority.Result {
	t.Helper()
	f := tr.f
	raw := f.actionAs(t, amount, run, ids.NewV7(), f.env.String(), tr.wl.inst.Instance.String())
	res, err := f.svc.Authorize(context.Background(), f.gw, raw, f.creds(t, tr.wl, tr.wl.token))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// t008DecisiveLevel is the grant level the decisive checklist item names.
func t008DecisiveLevel(res authority.Result) string {
	for _, it := range res.Checklist {
		if it.Decisive {
			return it.Level
		}
	}
	return ""
}

// t008Amount bounds refunds to at most limit USD each.
func t008Amount(limit string) string {
	return `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "` + limit + `"}}}}}`
}

// TestT008_AChildCannotTakeMoreThanItsParent (T-008, HR-045, HR-047): a
// workload delegating from its run's grant asks for more than that grant
// holds, one dimension at a time (operations, targets, amounts, lifetime,
// delegation depth and fan-out), or delegates from a grant that allows no
// delegation at all. The Delegate use case refuses each one, and the child
// run it started is left with no authority: an action in it is DENY
// NO_GRANT.
func TestT008_AChildCannotTakeMoreThanItsParent(t *testing.T) {
	tr := t008NewTree(t, clock.System{})
	root := tr.issue(t, t008Terms{bounds: t008Refunds, delegation: gdomain.Delegation{Depth: 2, MaxChildren: 3}, lifetime: 48 * time.Hour})
	rootRun := tr.start(t, root.ID)
	closedRun := tr.start(t, tr.issue(t, t008Terms{bounds: t008Refunds, lifetime: 48 * time.Hour}).ID)
	for name, tc := range map[string]struct {
		parent ids.UUID
		req    grantsapp.DelegateRequest
	}{
		"every payments operation":          {rootRun, grantsapp.DelegateRequest{Bounds: t008Bounds(t, `{"operations": ["payments.*"]}`)}},
		"charges outside the parent's":      {rootRun, grantsapp.DelegateRequest{Bounds: t008Bounds(t, `{"targets": {"payments.charge": {"prefixes": ["c"]}}}`)}},
		"larger refunds":                    {rootRun, grantsapp.DelegateRequest{Bounds: t008Bounds(t, t008Amount("500.00"))}},
		"a later expiry":                    {rootRun, grantsapp.DelegateRequest{ExpiresAt: root.ExpiresAt.Add(time.Hour)}},
		"the parent's own delegation depth": {rootRun, grantsapp.DelegateRequest{Delegation: gdomain.Delegation{Depth: 2, MaxChildren: 1}}},
		"more children than the parent":     {rootRun, grantsapp.DelegateRequest{Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 4}}},
		"from a grant that cannot delegate": {closedRun, grantsapp.DelegateRequest{Bounds: t008Bounds(t, t008Amount("20.00"))}},
	} {
		child, _, err := tr.delegate(t, tc.parent, tc.req)
		if reason := pcerr.ReasonOf(err); reason != "OUTSIDE_ALLOWED_AUTHORITY" {
			t.Errorf("%s: delegation = %v (%s), want OUTSIDE_ALLOWED_AUTHORITY", name, err, reason)
			continue
		}
		wantDecision(t, name+": the refused child run", tr.refund(t, child, "10.00"), domain.Deny, gdomain.ReasonNoGrant, "")
	}
}

// TestT008_AGrandchildCannotWidenWhatItsParentNarrowed (T-008, HR-045,
// HR-046, HR-047): the root grant allows refunds up to 100 USD and two
// levels of delegation; the child narrows them to 20 USD. The grandchild
// cannot take 50 USD back, although the root would allow it; with its
// bounds left open it inherits the child's 20 USD, not the root's 100, and
// the child's level is what refuses its 50 USD refund at decision time.
// Below the grandchild nothing can be delegated: the depth is used up.
func TestT008_AGrandchildCannotWidenWhatItsParentNarrowed(t *testing.T) {
	tr := t008NewTree(t, clock.System{})
	root := tr.issue(t, t008Terms{bounds: t008Refunds, delegation: gdomain.Delegation{Depth: 2, MaxChildren: 3}, lifetime: 48 * time.Hour})
	childRun, child := tr.mustDelegate(t, tr.start(t, root.ID), grantsapp.DelegateRequest{
		Bounds: t008Bounds(t, t008Amount("20.00")), Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 1},
	})
	if _, _, err := tr.delegate(t, childRun, grantsapp.DelegateRequest{Bounds: t008Bounds(t, t008Amount("50.00"))}); pcerr.ReasonOf(err) != "OUTSIDE_ALLOWED_AUTHORITY" {
		t.Fatalf("a grandchild took back what its parent narrowed: %v", err)
	}
	grandRun, grand := tr.mustDelegate(t, childRun, grantsapp.DelegateRequest{})
	if grand.Depth != 2 || grand.Parent != child.ID {
		t.Fatalf("grandchild %+v", grand)
	}
	over := tr.refund(t, grandRun, "50.00")
	wantDecision(t, "a 50 USD refund by the grandchild", over, domain.Deny, gdomain.ReasonGrantLimitExceeded, "")
	if level := t008DecisiveLevel(over); !strings.Contains(level, child.ID.String()) {
		t.Errorf("the refusal names %q, want the child grant %s that narrowed it", level, child.ID)
	}
	if res := tr.refund(t, grandRun, "15.00"); res.Decision != domain.Allow || res.Permit == "" {
		t.Fatalf("a 15 USD refund by the grandchild: %s %+v", res.Decision, res.Reasons)
	}
	if _, _, err := tr.delegate(t, grandRun, grantsapp.DelegateRequest{}); pcerr.ReasonOf(err) != "OUTSIDE_ALLOWED_AUTHORITY" {
		t.Fatalf("a third level was delegated below a depth of 2: %v", err)
	}
}

// TestT008_RevokingAGrantStopsItsWholeSubtreeAtOnce (T-008, HR-047, HR-002):
// a person revokes the middle grant of a root → child → grandchild chain.
// The revocation takes the grandchild with it in the same step: the permit
// the grandchild already holds can no longer be dispatched, its next action
// and the child's are DENY GRANT_REVOKED, and the child's run cannot hand
// its revoked authority to a new child run. The root, above the revoked
// grant, keeps its authority.
func TestT008_RevokingAGrantStopsItsWholeSubtreeAtOnce(t *testing.T) {
	tr := t008NewTree(t, clock.System{})
	root := tr.issue(t, t008Terms{bounds: t008Refunds, delegation: gdomain.Delegation{Depth: 2, MaxChildren: 3}, lifetime: 48 * time.Hour})
	rootRun := tr.start(t, root.ID)
	childRun, child := tr.mustDelegate(t, rootRun, grantsapp.DelegateRequest{Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 1}})
	grandRun, grand := tr.mustDelegate(t, childRun, grantsapp.DelegateRequest{})
	inflight := tr.refund(t, grandRun, "10.00")
	if inflight.Decision != domain.Allow || inflight.Permit == "" {
		t.Fatalf("the grandchild's refund before the revocation: %s %+v", inflight.Decision, inflight.Reasons)
	}

	revoked, err := tr.grants.Revoke(tr.f.ownerCtx(), child.ID, "compromised")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 2 || !slices.Contains(revoked, child.ID) || !slices.Contains(revoked, grand.ID) {
		t.Fatalf("revoked %v, want the child %s and the grandchild %s", revoked, child.ID, grand.ID)
	}
	if _, err := tr.f.svc.BeginDispatch(context.Background(), tr.f.gw, inflight.PermitID, inflight.Epoch, authority.Outbound{}); !errors.Is(err, authority.ErrEpochStale) {
		t.Fatalf("the grandchild's permit was dispatched after the revocation: %v", err)
	}
	wantDecision(t, "the grandchild after the revocation", tr.refund(t, grandRun, "10.00"), domain.Deny, gdomain.ReasonGrantRevoked, "")
	wantDecision(t, "the child after the revocation", tr.refund(t, childRun, "10.00"), domain.Deny, gdomain.ReasonGrantRevoked, "")
	if _, _, err := tr.delegate(t, childRun, grantsapp.DelegateRequest{}); pcerr.ReasonOf(err) != "OUTSIDE_ALLOWED_AUTHORITY" {
		t.Fatalf("the revoked child delegated again: %v", err)
	}
	if res := tr.refund(t, rootRun, "10.00"); res.Decision != domain.Allow {
		t.Fatalf("the root after its child's revocation: %s %+v", res.Decision, res.Reasons)
	}
}

// TestT008_AChildNeverOutlivesItsParent (T-008, HR-046, HR-047): the grant
// use cases run on a clock two hours behind the database, so what they did
// happened two hours before the Authority decides. A root grant issued then
// for ten hours cannot be delegated for longer; a child without an expiry
// gets the parent's. The person then cuts the root grant to end an hour
// ago (a narrowing revision); the child's own row still runs for eight more
// hours, yet at decision time the root's level stops it: DENY GRANT_EXPIRED
// naming the root grant's new revision.
func TestT008_AChildNeverOutlivesItsParent(t *testing.T) {
	issued := time.Now().Add(-2 * time.Hour)
	tr := t008NewTree(t, clock.NewFake(issued))
	root := tr.issue(t, t008Terms{bounds: t008Refunds, delegation: gdomain.Delegation{Depth: 1, MaxChildren: 1}, lifetime: 10 * time.Hour})
	rootRun := tr.start(t, root.ID)
	if _, _, err := tr.delegate(t, rootRun, grantsapp.DelegateRequest{ExpiresAt: root.ExpiresAt.Add(time.Minute)}); pcerr.ReasonOf(err) != "OUTSIDE_ALLOWED_AUTHORITY" {
		t.Fatalf("a child was delegated past its parent's expiry: %v", err)
	}
	childRun, child := tr.mustDelegate(t, rootRun, grantsapp.DelegateRequest{})
	// The parent as stored, to the database's microsecond.
	if child.ExpiresAt.After(root.ExpiresAt) || root.ExpiresAt.Sub(child.ExpiresAt) >= time.Microsecond {
		t.Fatalf("the child expires %s, its parent %s", child.ExpiresAt, root.ExpiresAt)
	}

	cut, _, err := tr.grants.Revise(tr.f.ownerCtx(), grantsapp.ReviseRequest{
		ID: root.ID, Revision: root.Revision, TaskRef: root.TaskRef, ExpiresAt: issued.Add(time.Hour),
		Bounds: root.Bounds, Requirements: root.Requirements, Limits: root.Limits, Delegation: root.Delegation,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := (&grantspg.Store{Pool: tr.f.pool}).Grant(context.Background(), tr.f.gw.Org, child.ID)
	if err != nil || !stored.ExpiresAt.After(time.Now().Add(7*time.Hour)) {
		t.Fatalf("the child's own row: expires %s, %v", stored.ExpiresAt, err)
	}
	res := tr.refund(t, childRun, "10.00")
	wantDecision(t, "the child after its parent ended", res, domain.Deny, gdomain.ReasonGrantExpired, "")
	if level := t008DecisiveLevel(res); !strings.Contains(level, root.ID.String()) || !strings.Contains(level, "revision 2") || cut.Revision != 2 {
		t.Errorf("the refusal names %q, want the root grant %s at revision 2", level, root.ID)
	}
	wantDecision(t, "the root after it ended", tr.refund(t, rootRun, "10.00"), domain.Deny, gdomain.ReasonGrantExpired, "")
}

// TestT008_AChildsOwnLimitsNeverLoosenItsAncestors (T-008, HR-046,
// HR-048): the root grant holds refunds over 50 USD for approval and has a
// 100 USD task budget. The workload delegates to its child without the
// approval requirement and with a 1,000 USD budget of the child's own. At
// decision time the root's requirement still holds the child's 60 USD
// refund, and the root's budget, shared with the child, stops the child
// after 90 USD and the root itself after that.
func TestT008_AChildsOwnLimitsNeverLoosenItsAncestors(t *testing.T) {
	tr := t008NewTree(t, clock.System{})
	root := tr.issue(t, t008Terms{
		bounds: t008Refunds, delegation: gdomain.Delegation{Depth: 1, MaxChildren: 1}, lifetime: 48 * time.Hour,
		limits: `{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"], "currency": "USD", "limit": "100", "period": "none"}]}`,
		requirements: `[{"operations": ["payments.refund.create"], "param": "amount", "unless": {"max": {"USD": "50.00"}},
		  "approval": {"role": "approver", "count": 1}, "reason": "REFUND_OVER_50"}]`,
	})
	rootRun := tr.start(t, root.ID)
	own, err := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "child", "grouping": "task", "operations": ["payments.refund.create"],
	  "currency": "USD", "limit": "1000", "period": "none"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	childRun, child := tr.mustDelegate(t, rootRun, grantsapp.DelegateRequest{Limits: own})
	if len(child.Requirements) != 0 {
		t.Fatalf("the child carries requirements %+v; the scenario needs a child that dropped them", child.Requirements)
	}

	wantDecision(t, "a 60 USD refund by the child", tr.refund(t, childRun, "60.00"), domain.RequireApproval, "REFUND_OVER_50", "")
	for i := range 3 {
		if res := tr.refund(t, childRun, "30.00"); res.Decision != domain.Allow {
			t.Fatalf("refund %d of 30 USD by the child: %s %+v", i+1, res.Decision, res.Reasons)
		}
	}
	over := tr.refund(t, childRun, "30.00")
	wantDecision(t, "the child past the root's budget", over, domain.Deny, gdomain.ReasonBudgetExhausted, "")
	if len(over.Reasons) > 0 && !strings.Contains(over.Reasons[0].Detail, root.ID.String()) {
		t.Errorf("the refusal %q does not name the root grant's budget", over.Reasons[0].Detail)
	}
	wantDecision(t, "the root after its child spent the budget", tr.refund(t, rootRun, "30.00"), domain.Deny, gdomain.ReasonBudgetExhausted, "")
}
