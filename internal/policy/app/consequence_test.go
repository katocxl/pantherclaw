// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestHR206_PolicySeesTheConsequenceBeingDecided: a rule reads
// `consequence` (G0 M8): whether the action is a consequence of another,
// its rule and state, whether it is unknown and its environments. For the
// action itself it is absent, so a rule written for consequences never
// matches it.
func TestHR206_PolicySeesTheConsequenceBeingDecided(t *testing.T) {
	f := newFixture(t)
	c, err := f.compile(
		refundRule("unknown", domain.Forbid, `consequence.unknown`),
		refundRule("payroll", domain.RequireApproval, `consequence.present && "payroll" in consequence.environments`),
	)
	if err != nil {
		t.Fatal(err)
	}
	a := f.refund("30.00", "duplicate")
	eval := func(cq *Consequence) domain.Outcome {
		t.Helper()
		out, err := c.Evaluate(context.Background(), f.def(a.Operation), a, Input{Budget: 10_000, Consequence: cq})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := eval(nil); out.Verdict != domain.VerdictPass {
		t.Errorf("the action itself: %+v", out)
	}
	if out := eval(&Consequence{Rule: "r", State: "UNKNOWN"}); out.Verdict != domain.VerdictDeny {
		t.Errorf("an unknown consequence: %+v", out)
	}
	if out := eval(&Consequence{Rule: "r", State: "PREDICTED", Environments: []string{"payroll"}}); out.Verdict != domain.VerdictRequireApproval {
		t.Errorf("a predicted payroll consequence: %+v", out)
	}
	if out := eval(&Consequence{Rule: "r", State: "PREDICTED", Environments: []string{"staging"}}); out.Verdict != domain.VerdictPass {
		t.Errorf("a predicted staging consequence: %+v", out)
	}
}
