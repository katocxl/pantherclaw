// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"pgregory.net/rapid"

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

// TestHR206_AnUnknownConsequenceAsksForWhatEveryOutcomeWould: an unknown
// consequence could be any of its outcomes, so its evaluation requires at
// least every requirement any predicted outcome would: whatever a
// requirement rule's condition says about the consequence's environments,
// rule or state, and whatever environment the rule is scoped to. A single
// code reviewer cannot release a merge that may deploy to production.
func TestHR206_AnUnknownConsequenceAsksForWhatEveryOutcomeWould(t *testing.T) {
	f := newFixture(t)
	envs := []string{"production", "staging", "payroll", "dev"}
	conds := []string{
		`"production" in consequence.environments`,
		`consequence.rule == "merge-triggers-deployment"`,
		`consequence.state == "PREDICTED" && size(consequence.environments) > 1`,
		`"staging" in consequence.environments && "payroll" in consequence.environments`,
		`consequence.present`,
		`true`,
	}
	a := f.refund("30.00", "duplicate")
	release := refundRule("release", domain.RequireApproval, `"production" in consequence.environments`)
	release.Approval = &domain.ApprovalRequirement{Role: "release_approver", Count: 1}
	c, err := f.compile(release)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Evaluate(context.Background(), f.def(a.Operation), a, Input{Budget: 10_000, Consequence: &Consequence{
		Rule: "merge-triggers-deployment", State: "UNKNOWN",
	}})
	if err != nil || out.Verdict != domain.VerdictRequireApproval || len(out.Approvals) != 1 || out.Approvals[0].Role != "release_approver" {
		t.Fatalf("an unknown deployment: %+v %v", out, err)
	}

	rapid.Check(t, func(rt *rapid.T) {
		var rules []domain.Rule
		for i := range rapid.IntRange(1, 6).Draw(rt, "rules") {
			kind := rapid.SampledFrom([]domain.Kind{domain.RequireApproval, domain.RequireStepUp}).Draw(rt, "kind")
			r := refundRule(fmt.Sprintf("r%d", i), kind, rapid.SampledFrom(conds).Draw(rt, "when"))
			if r.Approval != nil {
				r.Approval = &domain.ApprovalRequirement{Role: fmt.Sprintf("role%d", i), Count: 1}
			}
			if rapid.Bool().Draw(rt, "scoped") {
				r.Environments = []string{rapid.SampledFrom(envs).Draw(rt, "scope")}
			}
			rules = append(rules, r)
		}
		c, err := f.compile(rules...)
		if err != nil {
			rt.Fatal(err)
		}
		a := f.refund("30.00", "duplicate")
		a.Env = rapid.SampledFrom(envs).Draw(rt, "run env")
		eval := func(cq *Consequence) domain.Outcome {
			out, err := c.Evaluate(context.Background(), f.def(a.Operation), a, Input{Budget: 1_000_000, Consequence: cq})
			if err != nil {
				rt.Fatal(err)
			}
			return out
		}
		unknown := eval(&Consequence{Rule: "merge-triggers-deployment", State: "UNKNOWN"})
		outcome := eval(&Consequence{
			Rule: rapid.SampledFrom([]string{"merge-triggers-deployment", "other"}).Draw(rt, "rule"), State: "PREDICTED",
			Environments: rapid.SliceOfDistinct(rapid.SampledFrom(envs), func(s string) string { return s }).Draw(rt, "environments"),
		})
		for _, r := range outcome.Required {
			if !slices.ContainsFunc(unknown.Required, func(u domain.Required) bool { return u.Rule == r.Rule }) {
				rt.Fatalf("an outcome requires %s, the unknown consequence only %+v", r.Rule, unknown.Required)
			}
		}
	})
}
