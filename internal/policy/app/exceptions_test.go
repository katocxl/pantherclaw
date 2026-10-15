// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

const exceptionID = "01920000-0000-7000-8000-0000000000e1"

func exceptable(r domain.Rule) domain.Rule { r.Exceptable = true; return r }

// item finds a rule's checklist item.
func item(t *testing.T, out domain.Outcome, rule string) domain.Item {
	t.Helper()
	for _, it := range out.Checklist {
		if it.Rule == rule {
			return it
		}
	}
	t.Fatalf("no checklist item for %s in %+v", rule, out.Checklist)
	return domain.Item{}
}

// TestHR235_WaiverOnlyLiftsTheMatchedExceptableRule: a waived rule whose
// condition matches restricts nothing, names its exception and drops its
// obligation and requirement; the other rules decide as before.
func TestHR235_WaiverOnlyLiftsTheMatchedExceptableRule(t *testing.T) {
	f := newFixture(t)
	clamp := refundRule("batch-cap", domain.Constrain, "true")
	clamp.Constraint = &domain.Constraint{Kind: domain.CountMax, Param: "batch", Max: "1"}
	c, err := f.compile(
		exceptable(refundRule("no-large", domain.Forbid, `action.params.amount > money("1000.00", "USD")`)),
		exceptable(refundRule("approve-over-50", domain.RequireApproval, `action.params.amount > money("50.00", "USD")`)),
		exceptable(clamp),
		refundRule("step-up-fraud", domain.RequireStepUp, `action.params.reason == "fraudulent"`),
	)
	if err != nil {
		t.Fatal(err)
	}
	a := f.refund("5000.00", "fraudulent")
	waivers := map[string]string{"no-large": exceptionID, "approve-over-50": exceptionID, "batch-cap": exceptionID}
	out, err := c.Evaluate(context.Background(), f.def(a.Operation), a, Input{Budget: DefaultBudget, Waivers: waivers})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != domain.VerdictRequireStepUp {
		t.Fatalf("verdict %s, want the unwaived step-up to decide", out.Verdict)
	}
	for _, id := range []string{"no-large", "approve-over-50"} {
		if it := item(t, out, id); it.Status != domain.StatusWaived || it.Reason != domain.ReasonExceptionApplied ||
			it.Detail != exceptionID || it.Verdict != domain.VerdictPass {
			t.Fatalf("%s: %+v", id, it)
		}
	}
	if len(out.Approvals) != 0 || len(out.Obligations) != 0 {
		t.Fatalf("a waived rule kept its requirement or obligation: %+v %+v", out.Approvals, out.Obligations)
	}
	for _, r := range out.Required {
		if r.Rule == "approve-over-50" {
			t.Fatalf("a waived requirement is still required: %+v", r)
		}
	}
	// Not matched: nothing to waive, so it passes as usual.
	small := f.refund("10.00", "duplicate")
	out, err = c.Evaluate(context.Background(), f.def(small.Operation), small, Input{Budget: DefaultBudget, Waivers: waivers})
	if err != nil {
		t.Fatal(err)
	}
	if it := item(t, out, "no-large"); it.Status != domain.StatusPassed {
		t.Fatalf("an unmatched waived rule: %+v", it)
	}
}

// TestHR235_NonExceptableRuleIsNeverWaived: a waiver for a rule the
// publisher did not mark exceptable changes nothing, in the selection and
// in the engine.
func TestHR235_NonExceptableRuleIsNeverWaived(t *testing.T) {
	f := newFixture(t)
	forbid := refundRule("no-large", domain.Forbid, `action.params.amount > money("1000.00", "USD")`)
	c, err := f.compile(forbid)
	if err != nil {
		t.Fatal(err)
	}
	a := f.refund("5000.00", "duplicate")
	out, err := c.Evaluate(context.Background(), f.def(a.Operation), a,
		Input{Budget: DefaultBudget, Waivers: map[string]string{"no-large": exceptionID}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != domain.VerdictDeny {
		t.Fatalf("verdict %s, want DENY", out.Verdict)
	}
	d := domain.RuleDigest(forbid)
	x := domain.Exception{ID: exceptionID, Bundle: "test", Rule: "no-large", RuleDigest: hex.EncodeToString(d[:]), Operations: []string{a.Operation}}
	if w := domain.Waivers(c.Bundle, a.Operation, []domain.Exception{x}); w != nil {
		t.Fatalf("waivers for a non-exceptable rule: %v", w)
	}
}

// TestHR235_MissingFactIsNeverWaived: an exceptable rule whose fact is
// missing is not evaluated, so it cannot be waived: CANNOT_AUTHORIZE as
// without the exception (F096).
func TestHR235_MissingFactIsNeverWaived(t *testing.T) {
	f := newFixture(t)
	review := exceptable(refundRule("bank-review", domain.RequireApproval, `facts.payments_customer_bank_changed > now - 259200`))
	review.Facts = []domain.FactRef{{Name: "payments.customer.bank_changed", MaxAgeSeconds: 300}}
	c, err := f.compileWithFacts(review)
	if err != nil {
		t.Fatal(err)
	}
	a := f.refund("10.00", "duplicate")
	facts := map[string]fdomain.Value{"payments.charge.refundable": {Type: fdomain.TypeBoolean, Bool: true}}
	out, err := c.Evaluate(context.Background(), f.def(a.Operation), a,
		Input{Budget: DefaultBudget, Facts: facts, Now: decisionTime, Waivers: map[string]string{"bank-review": exceptionID}})
	if err != nil {
		t.Fatal(err)
	}
	if it := item(t, out, "bank-review"); out.Verdict != domain.VerdictCannotAuthorize || it.Status != domain.StatusNotEvaluated {
		t.Fatalf("verdict %s, item %+v", out.Verdict, it)
	}
	// With the fact present and matching, the same waiver applies.
	facts["payments.customer.bank_changed"] = fdomain.Value{Type: fdomain.TypeTimestamp, Int: decisionTime.Add(-time.Hour).Unix()}
	out, err = c.Evaluate(context.Background(), f.def(a.Operation), a,
		Input{Budget: DefaultBudget, Facts: facts, Now: decisionTime, Waivers: map[string]string{"bank-review": exceptionID}})
	if err != nil {
		t.Fatal(err)
	}
	if it := item(t, out, "bank-review"); out.Verdict != domain.VerdictPass || it.Status != domain.StatusWaived {
		t.Fatalf("verdict %s, item %+v", out.Verdict, it)
	}
}

// TestHR235_RuleDigestChangeEndsTheWaiver: an exception names the rule as
// it was requested in its bundle; once the rule changes, for an operation
// it does not list, or in another bundle, it waives nothing.
func TestHR235_RuleDigestChangeEndsTheWaiver(t *testing.T) {
	r := exceptable(refundRule("approve-over-50", domain.RequireApproval, `action.params.amount > money("50.00", "USD")`))
	d := domain.RuleDigest(r)
	x := domain.Exception{ID: exceptionID, Bundle: "test", Rule: r.ID, RuleDigest: hex.EncodeToString(d[:]), Operations: []string{"payments.refund.create"}}
	b := &domain.Bundle{ID: "test", Version: 1, Rules: []domain.Rule{r}}
	if w := domain.Waivers(b, "payments.refund.create", []domain.Exception{x}); w[r.ID] != exceptionID {
		t.Fatalf("waivers %v", w)
	}
	if w := domain.Waivers(b, "payments.refund.cancel", []domain.Exception{x}); w != nil {
		t.Fatalf("an unlisted operation was waived: %v", w)
	}
	other := x
	other.Bundle = "other-policy"
	if w := domain.Waivers(b, "payments.refund.create", []domain.Exception{other}); w != nil {
		t.Fatalf("an exception of another bundle was applied: %v", w)
	}
	changed := r
	changed.When = `action.params.amount > money("500.00", "USD")`
	b2 := &domain.Bundle{ID: "test", Version: 2, Rules: []domain.Rule{changed}}
	if w := domain.Waivers(b2, "payments.refund.create", []domain.Exception{x}); w != nil {
		t.Fatalf("a changed rule was waived: %v", w)
	}
	// The lowest id wins when two exceptions qualify.
	y := x
	y.ID = "01920000-0000-7000-8000-0000000000e0"
	if w := domain.Waivers(b, "payments.refund.create", []domain.Exception{x, y}); w[r.ID] != y.ID {
		t.Fatalf("waivers %v, want %s", w, y.ID)
	}
}
