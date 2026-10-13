// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// payoutPackage is the reference package with a payout consequence.
func payoutPackage(raw []byte) []byte { return []byte(pipelinetest.PayoutConsequence(string(raw))) }

// payouts records the charge's payout schedule, observed ago before now.
func (f *fx) payouts(charge string, members map[string]any, ago time.Duration) {
	f.w.PutFact(fdomain.Fact{
		Name: "payments.charge.payouts", SubjectType: "payments.charge", SubjectID: charge,
		Value: fdomain.Value{Type: fdomain.TypeObject, Object: members}, ObservedAt: now.Add(-ago), RecordedAt: now, ProviderID: f.provider,
	})
}

// payoutRun is a run under a grant that covers payouts, with an approval
// required for them when approve is set.
func (f *fx) payoutRun(approve bool) {
	f.t.Helper()
	g := f.newGrant(pipelinetest.PayoutBounds)
	if approve {
		g.Requirements = []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.payout.trigger"}, Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
			Reason: "PAYOUT_NEEDS_APPROVAL",
		}}
	}
	f.w.Grants.Put(g)
	f.run = f.newRun(g.ID)
}

func consequenceItem(ev *pipeline.Evaluation) bool {
	return slices.ContainsFunc(ev.Checklist, func(it pipeline.Item) bool {
		return strings.Contains(it.Level+it.Detail, "(consequence payments.payout.trigger on ch_1)")
	})
}

var scheduled = map[string]any{"state": "scheduled", "environments": []any{"payroll"}}

// TestHR206_APredictedConsequenceIsDecidedWithTheAction: a refund that
// starts a payout is decided with the payout under the same run, grant
// and policy (design decision 6): a grant that does not cover the payout
// denies the refund, its approval requirement holds the refund, a policy
// FORBID on payouts denies it, and a rule that is not triggered changes
// nothing.
func TestHR206_APredictedConsequenceIsDecidedWithTheAction(t *testing.T) {
	f := newFxWith(t, payoutPackage, "")
	f.payouts("ch_1", scheduled, time.Second)
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	if ev.Decision != adomain.Deny || !consequenceItem(ev) || len(ev.Consequences) != 1 || ev.Consequences[0].State != consequences.Predicted ||
		!slices.Equal(ev.Consequences[0].Environments, []string{"payroll"}) {
		t.Fatalf("a payout the grant does not cover: %s %+v %+v", ev.Decision, ev.Checklist, ev.Consequences)
	}

	f.payoutRun(true)
	ev = f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	if ev.Decision != adomain.RequireApproval || len(ev.Requirements) != 1 || ev.Requirements[0].Role != "approver" ||
		!strings.Contains(ev.Requirements[0].Source.Level, "(consequence payments.payout.trigger on ch_1)") {
		t.Fatalf("a payout that needs an approval: %s %+v", ev.Decision, ev.Requirements)
	}
	if err := f.w.SetPolicy([]pdomain.Rule{{
		ID: "no-payouts", Kind: pdomain.Forbid, Summary: "no payouts from refunds", Operations: []string{"payments.payout.trigger"},
		When: "true", Reason: "NO_PAYOUTS",
	}}, nil); err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, "NO_PAYOUTS")

	// Without a payout, neither the payout's approval nor its FORBID rule
	// applies to the refund.
	f.payouts("ch_1", map[string]any{"state": "none", "environments": []any{}}, time.Second)
	ev = f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
	if ev.Consequences[0].State != consequences.NotTriggered || consequenceItem(ev) {
		t.Fatalf("not triggered: %+v", ev.Consequences)
	}
}

// TestHR206_AnUnknownConsequenceIsAtLeastAHold: a payout schedule that is
// missing, stale or unknown leaves the payout UNKNOWN: the refund is held
// as "Consequence unknown" with the payout's requirements, CANNOT_AUTHORIZE
// when no requirement could release it, and a DENY still wins. It is never
// allowed.
func TestHR206_AnUnknownConsequenceIsAtLeastAHold(t *testing.T) {
	for name, fact := range map[string]func(f *fx){
		"missing": func(*fx) {},
		"stale":   func(f *fx) { f.payouts("ch_1", scheduled, time.Minute) },
		"unknown": func(f *fx) {
			f.payouts("ch_1", map[string]any{"state": "none", "unknown": "the schedule changed"}, time.Second)
		},
	} {
		f := newFxWith(t, payoutPackage, "")
		fact(f)
		ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
		if ev.Decision != adomain.Deny || len(ev.Consequences) != 1 || ev.Consequences[0].State != consequences.Unknown {
			t.Errorf("%s, a payout the grant does not cover: %s %+v", name, ev.Decision, ev.Consequences)
		}
		f.payoutRun(true)
		ev = f.call(f.run, "create_refund", refund("ch_1", "30.00"))
		expect(t, ev, adomain.RequireApproval, consequences.ReasonUnknown)
		if len(ev.Requirements) != 1 || ev.Requirements[0].Role != "approver" || !strings.HasPrefix(ev.Checklist[0].Detail, "Consequence unknown") {
			t.Errorf("%s, held: %+v %+v", name, ev.Requirements, ev.Checklist[0])
		}
		f.payoutRun(false)
		expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, consequences.ReasonUnknown)
	}
}

// TestHR206_ARuleThatCannotBeEvaluatedIsCannotAuthorize: a rule whose
// condition fails on the facts it reads is CANNOT_AUTHORIZE (HR-040),
// never "not triggered".
func TestHR206_ARuleThatCannotBeEvaluatedIsCannotAuthorize(t *testing.T) {
	f := newFxWith(t, payoutPackage, "")
	f.payoutRun(false)
	f.payouts("ch_1", map[string]any{"environments": []any{"payroll"}}, time.Second)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, consequences.ReasonEvaluation)
}

// TestHR206_PolicyMayForbidAnUnknownConsequenceButNeverClearIt: policy
// sees the consequence it decides (§43.3): a FORBID on consequence.unknown
// denies a refund whose payout cannot be ruled out, while a predicted
// payout gets the rule written for it. Nothing a requirement's condition
// says clears an unknown payout: it holds as "Consequence unknown" with
// every requirement a predicted payout could need (the union, M8.md:396,
// amended 2026-10-13), and with no requirement that covers payouts at all,
// the refund cannot be authorized.
func TestHR206_PolicyMayForbidAnUnknownConsequenceButNeverClearIt(t *testing.T) {
	predictedOnly := pdomain.Rule{
		ID: "approve-payouts", Kind: pdomain.RequireApproval, Summary: "payouts need an approver", Operations: []string{"payments.payout.trigger"},
		When: "!consequence.unknown", Reason: "PAYOUT_APPROVAL", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
	forbidUnknown := pdomain.Rule{
		ID: "no-unknown-payouts", Kind: pdomain.Forbid, Summary: "no payout that cannot be ruled out",
		Operations: []string{"payments.payout.trigger"}, When: "consequence.unknown", Reason: "UNKNOWN_PAYOUT",
	}
	f := newFxWith(t, payoutPackage, "")
	f.payoutRun(false)
	if err := f.w.SetPolicy([]pdomain.Rule{predictedOnly, forbidUnknown}, nil); err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, "UNKNOWN_PAYOUT")
	f.payouts("ch_1", scheduled, time.Second)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.RequireApproval, "PAYOUT_APPROVAL")

	f = newFxWith(t, payoutPackage, "")
	f.payoutRun(false)
	if err := f.w.SetPolicy([]pdomain.Rule{predictedOnly}, nil); err != nil {
		t.Fatal(err)
	}
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.RequireApproval, consequences.ReasonUnknown)
	if len(ev.Approvals) != 1 || ev.Approvals[0].Role != "approver" {
		t.Fatalf("an unknown payout holds for %+v, want the predicted payouts' approver", ev.Approvals)
	}

	f = newFxWith(t, payoutPackage, "")
	f.payoutRun(false)
	if err := f.w.SetPolicy([]pdomain.Rule{approvalOver50()}, nil); err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, consequences.ReasonUnknown)
}

// TestF158_TheHeldActionsDisplayShowsItsConsequences (G0 M8): the display an
// approver reads, and the binding hashes, names each predicted or unknown
// consequence with its environments, the workflows its facts name and why
// it is unknown; the decider rules say which approvals count only inside a
// change window.
func TestF158_TheHeldActionsDisplayShowsItsConsequences(t *testing.T) {
	f := newFxWith(t, payoutPackage, "")
	g := f.newGrant(pipelinetest.PayoutBounds)
	g.Requirements = []gdomain.Requirement{{
		Operations: gdomain.Ops{"payments.payout.trigger"}, Reason: "PAYOUT_NEEDS_A_RELEASE",
		Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1, Window: true},
	}}
	f.w.Grants.Put(g)
	f.run = f.newRun(g.ID)
	f.payouts("ch_1", map[string]any{
		"state": "scheduled", "environments": []any{"payroll"},
		"workflows": []any{map[string]any{"path": ".github/workflows/payouts.yml", "environments": []any{"payroll"}}},
	}, time.Second)
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	if ev.Decision != adomain.RequireApproval || ev.Hold == nil || len(ev.Hold.Display.Consequences) != 1 {
		t.Fatalf("held: %s %+v", ev.Decision, ev.Hold)
	}
	c := ev.Hold.Display.Consequences[0]
	if c.State != "PREDICTED" || c.Operation != "payments.payout.trigger" || !slices.Equal(c.Environments, []string{"payroll"}) ||
		!slices.Equal(c.Workflows, []string{".github/workflows/payouts.yml"}) || len(ev.Hold.Display.Deciders) != 1 || !ev.Hold.Display.Deciders[0].Window {
		t.Fatalf("display %+v deciders %+v", c, ev.Hold.Display.Deciders)
	}
}

// TestHR206_ConsequenceRulesReadTheirFactsAboutTheConsequence: a policy
// rule scoped to a consequence's operation reads its facts about the
// consequence's own target, which step 6 reads with the action's facts. A
// FORBID on a held payout account denies the refund and a REQUIRE holds
// it, where both were CANNOT_AUTHORIZE for a fact never read; the same
// fact about the action's target does not count for the consequence, and
// the facts read join the approval's display.
func TestHR206_ConsequenceRulesReadTheirFactsAboutTheConsequence(t *testing.T) {
	// The payout is about charge ch_10 when the refund is about ch_1.
	payoutElsewhere := func(raw []byte) []byte {
		return []byte(strings.Replace(string(payoutPackage(raw)), "      effect: funds.transfer\n",
			"      effect: funds.transfer\n      target: '{target.id}0'\n", 1))
	}
	held := func(f *fx, charge string, v bool) {
		f.w.PutFact(fdomain.Fact{
			Name: "payments.charge.held", SubjectType: "payments.charge", SubjectID: charge,
			Value: fdomain.Value{Type: fdomain.TypeBoolean, Bool: v}, ObservedAt: now.Add(-time.Second), RecordedAt: now, ProviderID: f.provider,
		})
	}
	rule := func(kind pdomain.Kind) pdomain.Rule {
		r := pdomain.Rule{
			ID: "held-payouts", Kind: kind, Summary: "payouts to a held account", Operations: []string{"payments.payout.trigger"},
			When: "facts.payments_charge_held", Reason: "PAYOUT_HELD",
			Facts: []pdomain.FactRef{{Name: "payments.charge.held", MaxAgeSeconds: 300}},
		}
		if kind == pdomain.RequireApproval {
			r.Approval = &pdomain.ApprovalRequirement{Role: "approver", Count: 1}
		}
		return r
	}
	catalog := map[string]fdomain.Type{"payments.charge.held": fdomain.TypeBoolean}

	f := newFxWith(t, payoutElsewhere, "")
	f.payoutRun(false)
	f.payouts("ch_1", scheduled, time.Second)
	if err := f.w.SetPolicy([]pdomain.Rule{rule(pdomain.Forbid)}, catalog); err != nil {
		t.Fatal(err)
	}
	held(f, "ch_1", true)
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.CannotAuthorize, pdomain.ReasonFactMissing)
	if len(ev.Consequences) != 1 || ev.Consequences[0].Target.ID != "ch_10" {
		t.Fatalf("the payout's target: %+v", ev.Consequences)
	}
	held(f, "ch_10", true)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, "PAYOUT_HELD")
	held(f, "ch_10", false)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Allow, pipeline.ReasonGrantCovers)

	if err := f.w.SetPolicy([]pdomain.Rule{rule(pdomain.RequireApproval)}, catalog); err != nil {
		t.Fatal(err)
	}
	held(f, "ch_10", true)
	ev = f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	if ev.Decision != adomain.RequireApproval || len(ev.Requirements) != 1 || ev.Requirements[0].Role != "approver" ||
		!strings.Contains(ev.Requirements[0].Source.Level, "(consequence payments.payout.trigger on ch_10)") {
		t.Fatalf("a held payout that needs an approval: %s %+v %+v", ev.Decision, ev.Requirements, ev.Checklist)
	}
	if ev.Hold == nil || !slices.ContainsFunc(ev.Hold.Display.Facts, func(l apdomain.FactLine) bool {
		return l.Name == "payments.charge.held" && l.Subject == "payments.charge:ch_10"
	}) {
		t.Fatalf("the payout's fact is not shown: %+v", ev.Hold)
	}
}
