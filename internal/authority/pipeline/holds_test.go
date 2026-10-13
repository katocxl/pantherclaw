// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"strings"
	"testing"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// heldFx is the fixture with the "refunds over 50 USD need an approver"
// policy, and one held 85 USD refund as (run, action).
func heldFx(t *testing.T) (*fx, pipeline.Request, *pipeline.Evaluation) {
	t.Helper()
	f := newFx(t)
	if err := f.w.SetPolicy([]pdomain.Rule{approvalOver50()}, nil); err != nil {
		t.Fatal(err)
	}
	req := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "85.00"))
	ev := f.eval(req)
	expect(t, ev, adomain.RequireApproval, "REFUND_OVER_50")
	return f, req, ev
}

// recorded is the request a hold finalization would record for ev.
func recorded(ev *pipeline.Evaluation, state apdomain.State) *pipeline.HoldRequest {
	h := &pipeline.HoldRequest{
		ID: ids.NewV7(), State: state, Binding: ev.Hold.Binding.Hash, Deadline: ev.Hold.Deadline,
		Variants: ev.Hold.Display.Variants, Context: ev.Hold.Display.Context,
	}
	if state == apdomain.StateApproved {
		by := now.Add(15 * time.Minute)
		h.ConsumeBy = &by
	}
	return h
}

// TestHR030_AHoldCarriesItsBindingDisplayAndSources: a held action gets
// the merged requirements with their sources, a one-hour deadline in whole
// seconds, the display rendered from the template and the binding over it.
func TestHR030_AHoldCarriesItsBindingDisplayAndSources(t *testing.T) {
	_, _, ev := heldFx(t)
	h := ev.Hold
	if h == nil || h.Keep || h.Satisfied || h.State != apdomain.WaitPending {
		t.Fatalf("hold = %+v", h)
	}
	if len(h.Requirements) != 1 || h.Requirements[0].Role != "approver" ||
		h.Requirements[0].Sources[0].Level != "policy org-policy@1 rule approve-over-50" {
		t.Fatalf("requirements %+v", h.Requirements)
	}
	if !h.Deadline.Equal(now.Add(time.Hour)) || h.Display.Title != "Refund 85.00 USD on charge ch_1" {
		t.Fatalf("deadline %s, title %q", h.Deadline, h.Display.Title)
	}
	if h.Binding.Hash == [32]byte{} || !strings.Contains(string(h.Binding.Input), `"jkt":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"`) {
		t.Fatalf("binding input %s", h.Binding.Input)
	}
}

// TestHR031_AnApprovalWithTheSameBindingSatisfiesTheRequirement: the
// resubmission re-runs the whole pipeline, recomputes the binding with the
// stored deadline, and an APPROVED request with that binding satisfies the
// requirement; one with another binding never does.
func TestHR031_AnApprovalWithTheSameBindingSatisfiesTheRequirement(t *testing.T) {
	f, req, ev := heldFx(t)
	f.w.SetHold(f.run, actionOf(req), recorded(ev, apdomain.StatePending))
	again := f.eval(req)
	expect(t, again, adomain.RequireApproval, "REFUND_OVER_50")
	if !again.Hold.Keep || again.Hold.Binding.Hash != ev.Hold.Binding.Hash {
		t.Fatal("an unchanged resubmission does not keep its request")
	}

	f.w.SetHold(f.run, actionOf(req), recorded(ev, apdomain.StateApproved))
	ok := f.eval(req)
	expect(t, ok, adomain.Allow, pipeline.ReasonGrantCovers)
	if !ok.Hold.Satisfied || !ok.Hold.Keep {
		t.Fatalf("hold = %+v", ok.Hold)
	}

	other := recorded(ev, apdomain.StateApproved)
	other.Binding[0] ^= 1
	f.w.SetHold(f.run, actionOf(req), other)
	held := f.eval(req)
	expect(t, held, adomain.RequireApproval, "REFUND_OVER_50")
	if held.Hold.Keep || held.Hold.Satisfied {
		t.Fatal("an approval of another binding was used")
	}
}

// TestHR031_AStricterRequirementAfterApprovalGivesANewRequest: when the
// policy asks for more after the approval, the binding changes and the old
// approval cannot be used (F193 scenario 6).
func TestHR031_AStricterRequirementAfterApprovalGivesANewRequest(t *testing.T) {
	f, req, ev := heldFx(t)
	f.w.SetHold(f.run, actionOf(req), recorded(ev, apdomain.StateApproved))
	stricter := approvalOver50()
	stricter.Approval = &pdomain.ApprovalRequirement{Role: "approver", Count: 2}
	if err := f.w.SetPolicy([]pdomain.Rule{stricter}, nil); err != nil {
		t.Fatal(err)
	}
	again := f.eval(req)
	expect(t, again, adomain.RequireApproval, "REFUND_OVER_50")
	if again.Hold.Keep || again.Hold.Satisfied || again.Hold.Binding.Hash == ev.Hold.Binding.Hash {
		t.Fatal("the approval survived a stricter requirement")
	}
	// A changed bound fact member ends the approval too (F193 scenario 6,
	// completed; HR-030 as the founder amended it on 2026-10-13): the action
	// no longer matches its fact.
	b, breq, bev := boundHeldFx(t)
	b.w.SetHold(b.run, actionOf(breq), recorded(bev, apdomain.StateApproved))
	b.state("ch_1", map[string]any{"reason": "fraudulent"})
	moved := b.eval(breq)
	if moved.Hold != nil && moved.Hold.Satisfied {
		t.Fatal("the approval survived a new bound value")
	}
	expect(t, moved, adomain.CannotAuthorize, "STATE_MOVED")
}

// boundHeldFx is heldFx with boundRefunds: the refund's reason is bound to
// the charge's state, whose reason is "duplicate".
func boundHeldFx(t *testing.T) (*fx, pipeline.Request, *pipeline.Evaluation) {
	t.Helper()
	f := newFxWith(t, boundRefunds, "")
	f.state("ch_1", map[string]any{"reason": "duplicate"})
	if err := f.w.SetPolicy([]pdomain.Rule{approvalOver50()}, nil); err != nil {
		t.Fatal(err)
	}
	req := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "85.00"))
	ev := f.eval(req)
	expect(t, ev, adomain.RequireApproval, "REFUND_OVER_50")
	return f, req, ev
}

// TestHR030_AnApprovalBindsOnlyTheMembersItsDefinitionBinds (option B,
// founder decision 2026-10-13): a fact observed again with the same value,
// or a change to a member nothing binds, keeps the approval usable; every
// fact is still read again when the approval is used, so a fact that now
// fails a check refuses the action even though it was approved.
func TestHR030_AnApprovalBindsOnlyTheMembersItsDefinitionBinds(t *testing.T) {
	f, req, ev := heldFx(t)
	f.w.SetHold(f.run, actionOf(req), recorded(ev, apdomain.StateApproved))
	f.putFact("ch_1", true, now.Add(-10*time.Second))
	again := f.eval(req)
	expect(t, again, adomain.Allow, pipeline.ReasonGrantCovers)
	if !again.Hold.Satisfied || again.Hold.Binding.Hash != ev.Hold.Binding.Hash {
		t.Fatal("a re-observed fact with the same value ended the approval")
	}

	b, breq, bev := boundHeldFx(t)
	b.w.SetHold(b.run, actionOf(breq), recorded(bev, apdomain.StateApproved))
	b.state("ch_1", map[string]any{"reason": "duplicate", "note": "re-checked"})
	if kept := b.eval(breq); kept.Decision != adomain.Allow || !kept.Hold.Satisfied || kept.Hold.Binding.Hash != bev.Hold.Binding.Hash {
		t.Fatalf("an unbound member ended the approval: %s %+v", kept.Decision, kept.Hold)
	}

	refundableOnly := pdomain.Rule{
		ID: "refundable-only", Kind: pdomain.Forbid, Summary: "only refundable charges",
		Operations: []string{"payments.refund.create"}, When: `!facts.payments_charge_refundable`, Reason: "NOT_REFUNDABLE",
	}
	c := newFx(t)
	if err := c.w.SetPolicy([]pdomain.Rule{approvalOver50(), refundableOnly}, map[string]fdomain.Type{"payments.charge.refundable": fdomain.TypeBoolean}); err != nil {
		t.Fatal(err)
	}
	creq := c.parse(c.run, ids.NewV7(), "create_refund", refund("ch_1", "85.00"))
	cev := c.eval(creq)
	expect(t, cev, adomain.RequireApproval, "REFUND_OVER_50")
	c.w.SetHold(c.run, actionOf(creq), recorded(cev, apdomain.StateApproved))
	c.putFact("ch_1", false, now.Add(-10*time.Second))
	expect(t, c.eval(creq), adomain.Deny, "NOT_REFUNDABLE")
}

// TestHR171_ADeclinedOrExpiredRequestEndsTheActionAsDeny: a decline, a
// narrower proposal, a deadline passed and an approval not used in time end
// the action as DENY, by the database clock and even when nothing is
// required any more (PAP-1 §7.1: terminal for that action id).
func TestHR171_ADeclinedOrExpiredRequestEndsTheActionAsDeny(t *testing.T) {
	past := now.Add(-time.Second)
	for _, c := range []struct {
		name   string
		mutate func(*pipeline.HoldRequest)
		code   string
		wait   string
		expire bool
	}{
		{"declined", func(h *pipeline.HoldRequest) {
			h.State, h.EndReason = apdomain.StateDeclined, apdomain.EndDeclined
		}, apdomain.ReasonApprovalDeclined, apdomain.WaitDeclined, false},
		{"narrower proposed", func(h *pipeline.HoldRequest) {
			h.State, h.EndReason, h.ProposedParams = apdomain.StateDeclined, apdomain.EndNarrowerProposed, []byte(`{"amount":{"value":"40.00","currency":"USD"}}`)
		}, apdomain.ReasonNarrowerProposed, apdomain.WaitNarrowerProposed, false},
		{"deadline passed, janitor not run", func(h *pipeline.HoldRequest) { h.Deadline = past }, apdomain.ReasonApprovalExpired, apdomain.WaitExpired, true},
		{"approved, not used in time", func(h *pipeline.HoldRequest) {
			h.State, h.ConsumeBy = apdomain.StateApproved, &past
		}, apdomain.ReasonApprovalExpired, apdomain.WaitExpired, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, req, ev := heldFx(t)
			h := recorded(ev, apdomain.StatePending)
			c.mutate(h)
			f.w.SetHold(f.run, actionOf(req), h)
			got := f.eval(req)
			expect(t, got, adomain.Deny, c.code)
			if got.Hold.State != c.wait || got.Hold.Expire != c.expire {
				t.Fatalf("hold %+v", got.Hold)
			}
			if err := f.w.SetPolicy([]pdomain.Rule{{
				ID: "other", Kind: pdomain.Annotate, Summary: "nothing required", Operations: []string{"payments.refund.get"},
				When: "true", Reason: "OTHER", Labels: map[string]string{"x": "y"},
			}}, nil); err != nil {
				t.Fatal(err)
			}
			expect(t, f.eval(req), adomain.Deny, c.code)
		})
	}
}

// TestHR170_StoredRequirementsThatCannotBeSatisfiedAreCannotAuthorize
// (decisions 2 and 4): a policy naming a role that is not a default
// approver role, or a step-up of a launcher that is not a person, never
// becomes a hold anyone could satisfy.
func TestHR170_StoredRequirementsThatCannotBeSatisfiedAreCannotAuthorize(t *testing.T) {
	f := newFx(t)
	old := approvalOver50()
	old.Approval = &pdomain.ApprovalRequirement{Role: "finance.approver", Count: 1}
	if err := f.w.SetPolicy([]pdomain.Rule{old}, nil); err != nil {
		t.Fatal(err)
	}
	ev := f.call(f.run, "create_refund", refund("ch_1", "85.00"))
	expect(t, ev, adomain.CannotAuthorize, apdomain.ReasonRequirementInvalid)
	if ev.Hold != nil {
		t.Fatal("an unsatisfiable requirement produced a hold")
	}

	stepUp := pdomain.Rule{
		ID: "step-up-over-50", Kind: pdomain.RequireStepUp, Summary: "the launcher confirms", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("50.00", "USD")`, Reason: "CONFIRM",
		StepUp: &pdomain.StepUpRequirement{Subject: "launcher", Method: "webauthn"},
	}
	if err := f.w.SetPolicy([]pdomain.Rule{stepUp}, nil); err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "85.00")), adomain.RequireStepUp, "CONFIRM")
	bot := gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: ids.NewV7()}
	run := ids.NewV7()
	f.w.AddRun(run, pipeline.Run{AgentID: f.agent, InstanceID: f.instance, Launcher: bot, Principal: f.alice, EnvironmentID: f.env, GrantID: f.grant.ID, Active: true})
	expect(t, f.call(run, "create_refund", refund("ch_1", "85.00")), adomain.CannotAuthorize, apdomain.ReasonStepUpSubjectNotAPerson)
}

// TestINV08_AnUnreadableApprovalRequestNeverAllows: when the transaction's
// request cannot be read, the decision is CANNOT_AUTHORIZE, never ALLOW,
// even for an action that needs no approval.
func TestINV08_AnUnreadableApprovalRequestNeverAllows(t *testing.T) {
	f := newFx(t)
	f.w.Fail["Hold"] = true
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "40.00")), adomain.CannotAuthorize, pipeline.ReasonEvidenceUnavailable)
	f.w.Fail["Hold"] = false
	if err := f.w.SetPolicy([]pdomain.Rule{approvalOver50()}, nil); err != nil {
		t.Fatal(err)
	}
	f.w.Fail["Variants"] = true
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "85.00")), adomain.CannotAuthorize, pipeline.ReasonEvidenceUnavailable)
}

func actionOf(req pipeline.Request) ids.UUID {
	id, err := ids.ParseUUID(req.Action.Action.ActionID)
	if err != nil {
		panic(err)
	}
	return id
}
