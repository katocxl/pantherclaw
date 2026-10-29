// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// disputed records whether the charge is disputed, a fact only the
// customer rule below reads.
func (f *fx) disputed(charge string, v bool) {
	f.w.PutFact(fdomain.Fact{
		Name: "payments.charge.disputed", SubjectType: "payments.charge", SubjectID: charge,
		Value: fdomain.Value{Type: fdomain.TypeBoolean, Bool: v}, ObservedAt: now.Add(-time.Second), RecordedAt: now, ProviderID: f.provider,
	})
}

// disputePays is an org's customer rule: a refund on a disputed charge
// starts a payout too.
func disputePays(id string, depth int) defs.ConsequenceRule {
	return defs.ConsequenceRule{
		ID: id, Operation: "payments.refund.create", When: "facts.payments_charge_disputed", RequiresFacts: []string{"payments.charge.disputed"},
		Consequence: defs.Consequence{Operation: "payments.payout.trigger", Effect: "funds.transfer", Description: "A disputed refund pays out"},
		ValidUntil:  "2027-10-08", MaxDepth: depth,
	}
}

func states(ev *pipeline.Evaluation) []string {
	var out []string
	for _, c := range ev.Consequences {
		out = append(out, c.Rule+":"+string(c.State)+":"+string(c.Source))
	}
	return out
}

// TestHR454_CustomerRulesOnlyAddRequirements: a customer rule's predicted
// consequence is decided with the action like a package one, after the
// package's rules, so the payout's approval applies though the package
// rule rules the payout out (F406, F408); a customer rule that is not
// triggered never clears a package consequence that is UNKNOWN; a
// customer consequence is never waived by an exception; and when the
// customer rules cannot be read the action cannot be authorized.
//
// Covers: F405, F406, F408
func TestHR454_CustomerRulesOnlyAddRequirements(t *testing.T) {
	none := map[string]any{"state": "none", "environments": []any{}}
	f := newFxWith(t, payoutPackage, "")
	f.payoutRun(true)
	f.payouts("ch_1", none, time.Second)
	f.disputed("ch_1", true)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Allow, pipeline.ReasonGrantCovers)

	f.w.SetCustomerRules(disputePays("cx.dispute-pays", 0))
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.RequireApproval, "PAYOUT_NEEDS_APPROVAL")
	if got := states(ev); !slices.Equal(got, []string{"refund-triggers-payout:NOT_TRIGGERED:package", "cx.dispute-pays:PREDICTED:customer"}) {
		t.Fatalf("consequences %q", got)
	}

	// The package rule cannot read its fact; the customer rule's holds
	// false. The payout is still not ruled out.
	f2 := newFxWith(t, payoutPackage, "")
	f2.payoutRun(true)
	f2.disputed("ch_1", false)
	f2.w.SetCustomerRules(disputePays("cx.dispute-pays", 0))
	ev = f2.call(f2.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.RequireApproval, consequences.ReasonUnknown)
	if got := states(ev); !slices.Equal(got, []string{"refund-triggers-payout:UNKNOWN:package", "cx.dispute-pays:NOT_TRIGGERED:customer"}) {
		t.Fatalf("consequences %q", got)
	}

	// An exception that waives a package payout does not waive the
	// customer one.
	noPayouts := pdomain.Rule{
		ID: "no-payouts", Kind: pdomain.Forbid, Summary: "no payouts from refunds", Operations: []string{"payments.payout.trigger"},
		When: "true", Reason: "NO_PAYOUTS", Exceptable: true,
	}
	f3 := newFxWith(t, payoutPackage, "")
	f3.payoutRun(false)
	if err := f3.w.SetPolicy([]pdomain.Rule{noPayouts}, nil); err != nil {
		t.Fatal(err)
	}
	d := pdomain.RuleDigest(noPayouts)
	f3.w.SetExceptions([]pdomain.Exception{{
		ID: exceptionID, Bundle: "org-policy", Rule: noPayouts.ID, RuleDigest: hex.EncodeToString(d[:]),
		Operations: []string{"payments.payout.trigger"}, ExpiresAt: now.Add(time.Hour),
	}})
	f3.payouts("ch_1", scheduled, time.Second)
	f3.disputed("ch_1", false)
	f3.w.SetCustomerRules(disputePays("cx.dispute-pays", 0))
	if ev := f3.call(f3.run, "create_refund", refund("ch_1", "30.00")); ev.Decision != adomain.Allow {
		t.Fatalf("a waived package payout: %s %+v", ev.Decision, ev.Checklist)
	}
	f3.disputed("ch_1", true)
	expect(t, f3.call(f3.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, "NO_PAYOUTS")

	f.w.Fail["CustomerRules"] = true
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, pipeline.ReasonEvidenceUnavailable)
}

// TestT199_ACustomerRuleCannotLoosen (T-199): an org member who writes a
// customer rule to get an action through gets no further: a rule that
// predicts nothing leaves the package's consequences and their
// requirements as they were, a rule whose consequence cannot be evaluated
// (its operation has no ACTIVE definition) is CANNOT_AUTHORIZE rather than
// ignored, and a replay of version 4 inputs, recorded before customer
// rules, never reads them.
//
// Covers: F405, F413
func TestT199_ACustomerRuleCannotLoosen(t *testing.T) {
	f := newFxWith(t, payoutPackage, "")
	f.payoutRun(true)
	f.payouts("ch_1", scheduled, time.Second)
	f.disputed("ch_1", false)
	f.w.SetCustomerRules(disputePays("cx.dispute-pays", 0))
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.RequireApproval, "PAYOUT_NEEDS_APPROVAL")

	ghost := disputePays("cx.ghost-op", 0)
	ghost.Consequence.Operation = "payments.ghost.trigger"
	f.disputed("ch_1", true)
	f.w.SetCustomerRules(ghost)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, consequences.ReasonEvaluation)

	f.w.SetCustomerRules(disputePays("cx.dispute-pays", 0))
	f.w.Fail["CustomerRules"] = true
	v4 := &pipeline.Pipeline{Reader: f.w, Replaying: 4}
	ev, err := v4.Evaluate(t.Context(), f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "30.00")))
	if err != nil || ev.Decision != adomain.RequireApproval || len(ev.Consequences) != 1 {
		t.Fatalf("version 4: %v %s %q", err, ev.Decision, states(ev))
	}
}

// TestT200_AConsequenceChainCannotExplodeOrLoop (T-200): customer rules
// that would give a refund more than 16 consequences stop at the 17th,
// which is UNKNOWN, CONSEQUENCE_FANOUT, so the refund is at least a hold;
// rules that predict the payout from the payout itself, all the way down,
// never derive it twice (HR-455).
//
// Covers: F411, F412
func TestT200_AConsequenceChainCannotExplodeOrLoop(t *testing.T) {
	f := newFxWith(t, payoutPackage, "")
	f.payoutRun(true)
	f.payouts("ch_1", map[string]any{"state": "none", "environments": []any{}}, time.Second)
	f.disputed("ch_1", true)
	var rules []defs.ConsequenceRule
	for i := range 20 {
		rules = append(rules, disputePays(fmt.Sprintf("cx.dispute-pays-%02d", i), 0))
	}
	f.w.SetCustomerRules(rules...)
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	last := ev.Consequences[len(ev.Consequences)-1]
	if len(ev.Consequences) != consequences.MaxConsequences+1 || last.State != consequences.Unknown || last.Reason != consequences.ReasonFanout {
		t.Fatalf("fanout: %d %+v", len(ev.Consequences), last)
	}
	if ev.Decision != adomain.RequireApproval || !slices.ContainsFunc(ev.Checklist, func(it pipeline.Item) bool { return it.Code == consequences.ReasonFanout }) {
		t.Fatalf("fanout decision %s %+v", ev.Decision, ev.Checklist)
	}

	loop := disputePays("cx.payout-pays-out", 4)
	loop.Operation = "payments.payout.trigger"
	f.w.SetCustomerRules(disputePays("cx.dispute-pays", 0), loop)
	ev = f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	if got := states(ev); !slices.Equal(got, []string{
		"refund-triggers-payout:NOT_TRIGGERED:package", "cx.dispute-pays:PREDICTED:customer", "cx.payout-pays-out:PREDICTED:customer",
	}) {
		t.Fatalf("loop: %q", got)
	}
}
