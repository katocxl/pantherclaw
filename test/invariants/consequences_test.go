// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package invariants_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// The payout schedule a consequence rule reads (pipelinetest's payout
// consequence, shaped as G0 M8's deployment consequences).
const (
	payoutMissing = iota
	payoutStale
	payoutUnknown
	payoutScheduled
	payoutNone
)

// payouts records the charge's payout schedule as kind says.
func (w *world) payouts(charge string, kind int) {
	members := map[string]any{"state": "scheduled", "environments": []any{"payroll"}}
	observed := now.Add(-time.Second)
	switch kind {
	case payoutMissing:
		return
	case payoutStale:
		observed = now.Add(-time.Minute)
	case payoutUnknown:
		members = map[string]any{"state": "none", "unknown": "a workflow changed"}
	case payoutNone:
		members = map[string]any{"state": "none", "environments": []any{}}
	}
	w.w.PutFact(fdomain.Fact{
		Name: "payments.charge.payouts", SubjectType: "payments.charge", SubjectID: charge,
		Value: fdomain.Value{Type: fdomain.TypeObject, Object: members}, ObservedAt: observed, ProviderID: ids.NewV7(),
	})
}

// payoutPolicies are the policies a property draws from: none, a FORBID on
// unknown payouts, a requirement for predicted payouts only, and a FORBID
// on every payout.
var payoutPolicies = [][]pdomain.Rule{
	nil,
	{{ID: "no-unknown", Kind: pdomain.Forbid, Summary: "s", Operations: []string{"payments.payout.trigger"}, When: "consequence.unknown", Reason: "UNKNOWN_PAYOUT"}},
	{{
		ID: "approve", Kind: pdomain.RequireApproval, Summary: "s", Operations: []string{"payments.payout.trigger"}, When: "!consequence.unknown",
		Reason: "PAYOUT_APPROVAL", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}},
	{{ID: "no-payouts", Kind: pdomain.Forbid, Summary: "s", Operations: []string{"payments.payout.trigger"}, When: "true", Reason: "NO_PAYOUTS"}},
}

// strictness orders decisions, strictest first (F092).
var strictness = []adomain.Decision{
	adomain.Deny, adomain.CannotAuthorize, adomain.RequireApproval, adomain.RequireStepUp, adomain.AllowWithObligations, adomain.Allow,
}

// payoutCase is one drawn situation, decided with or without the
// consequence rule.
type payoutCase struct {
	fact, policy    int
	covers, require bool
	charge, amount  string
	edit            func(string) string
}

func (c payoutCase) decide(t fataler) *pipeline.Evaluation {
	w := newWorldWith(t, c.edit)
	w.payouts(c.charge, c.fact)
	bounds := rootBounds
	if c.covers {
		bounds = pipelinetest.PayoutBounds
	}
	g := w.grant(bounds, w.alice)
	if c.require {
		g.Requirements = []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.payout.trigger"}, Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1}, Reason: "GRANT_PAYOUT",
		}}
		w.w.Grants.Put(g)
	}
	if rules := payoutPolicies[c.policy]; rules != nil {
		if err := w.w.SetPolicy(rules, nil); err != nil {
			t.Fatal(err)
		}
	}
	return w.eval(w.request(w.run(g.ID, w.alice), "create_refund", refundInput(c.charge, c.amount, "")))
}

// TestHR206_ConsequencesNeverLoosenADecision (T-083): whatever the facts,
// grant and policy, deciding a refund with its consequence rule is never
// looser than deciding it without; a payout that cannot be ruled out is
// never allowed; a payout the grant does not cover, or that a policy
// forbids, denies the refund.
func TestHR206_ConsequencesNeverLoosenADecision(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		c := payoutCase{
			fact: rapid.IntRange(payoutMissing, payoutNone).Draw(t, "fact"), policy: rapid.IntRange(0, len(payoutPolicies)-1).Draw(t, "policy"),
			covers: rapid.Bool().Draw(t, "covers"), require: rapid.Bool().Draw(t, "require"),
		}
		c.charge, c.amount = genRefund(t)
		plain := c.decide(t)
		c.edit = pipelinetest.PayoutConsequence
		with := c.decide(t)
		if slices.Index(strictness, with.Decision) > slices.Index(strictness, plain.Decision) {
			t.Fatalf("the consequence loosened %s to %s", plain.Decision, with.Decision)
		}
		consequence := c.fact != payoutNone
		switch {
		case c.fact <= payoutUnknown && with.Decision.Permits():
			t.Fatalf("an unknown payout was allowed: %s %+v", with.Decision, with.Checklist)
		case consequence && (!c.covers || c.policy == 3) && with.Decision != adomain.Deny:
			t.Fatalf("an uncovered or forbidden payout was not denied: %s %+v", with.Decision, with.Checklist)
		case !consequence && with.Decision != plain.Decision:
			t.Fatalf("a payout ruled out changed the decision: %s, not %s", with.Decision, plain.Decision)
		}
	})
}

// TestHR206_TheRuleScenariosKillEveryMutant: every mutant of the payout
// rule's condition (each comparison flipped, HR-044) decides one of a
// scheduled or a ruled-out payout differently, so the scenarios pin the
// rule's meaning.
func TestHR206_TheRuleScenariosKillEveryMutant(t *testing.T) {
	const when = "facts.payments_charge_payouts.state != 'none'"
	mutants, err := papp.Mutants(when)
	if err != nil || len(mutants) == 0 {
		t.Fatalf("mutants %v %v", mutants, err)
	}
	decisions := func(edit func(string) string) []adomain.Decision {
		var out []adomain.Decision
		for _, fact := range []int{payoutScheduled, payoutNone} {
			c := payoutCase{fact: fact, covers: true, require: true, charge: "ch_1", amount: "30.00", edit: edit}
			out = append(out, c.decide(t).Decision)
		}
		return out
	}
	want := decisions(pipelinetest.PayoutConsequence)
	if !slices.Equal(want, []adomain.Decision{adomain.RequireApproval, adomain.Allow}) {
		t.Fatalf("the reference rule decides %v", want)
	}
	for _, m := range mutants {
		got := decisions(func(pkg string) string { return strings.Replace(pipelinetest.PayoutConsequence(pkg), when, m, 1) })
		if slices.Equal(got, want) {
			t.Errorf("mutant %q survives", m)
		}
	}
}
