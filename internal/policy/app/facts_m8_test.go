// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strings"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestHR160_ObjectFactsAreReadByMember: a rule reads an object fact's
// members (G0 M8: facts.github_pull_head.sha); a member the fact lacks is
// an evaluation error, which fails the rule closed, never a default
// (HR-040).
func TestHR160_ObjectFactsAreReadByMember(t *testing.T) {
	f := newFixture(t)
	rule := refundRule("draft", domain.Forbid, `facts.github_pull_head.draft == true && size(facts.github_pull_head.failing) > 0`)
	rule.Facts = []domain.FactRef{{Name: "github.pull.head", MaxAgeSeconds: 30}}
	e := &Engine{Limits: celenv.DefaultLimits, Facts: map[string]fdomain.Type{"github.pull.head": fdomain.TypeObject}}
	c, err := e.Compile(&domain.Bundle{ID: "test", Version: 1, Rules: []domain.Rule{rule}}, []*defs.Definition{f.def("payments.refund.create")})
	if err != nil {
		t.Fatal(err)
	}
	eval := func(members map[string]any) domain.Verdict {
		t.Helper()
		out, err := c.Evaluate(context.Background(), f.def("payments.refund.create"), f.refund("30.00", "duplicate"), Input{
			Budget: DefaultBudget, Now: decisionTime,
			Facts: map[string]fdomain.Value{"github.pull.head": {Type: fdomain.TypeObject, Object: members}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return out.Verdict
	}
	if v := eval(map[string]any{"draft": true, "failing": []any{"test"}}); v != domain.VerdictDeny {
		t.Fatalf("a draft with failing checks: %s", v)
	}
	if v := eval(map[string]any{"draft": false, "failing": []any{}}); v != domain.VerdictPass {
		t.Fatalf("ready: %s", v)
	}
	// CEL absorbs an error into a false conjunction, so the member is missing
	// where the other side is true; the error fails the rule closed (HR-040).
	if v := eval(map[string]any{"failing": []any{"test"}}); v != domain.VerdictDeny {
		t.Fatalf("a missing member: %s", v)
	}
}

// TestHR206_ARuleOnAConsequenceReadsOnlyFactsAboutItsTarget: the Authority
// decides a consequence with facts about the consequence's own target, so a
// policy version whose rule on an operation that is only ever a consequence
// reads a fact declared about another kind of subject is refused when it is
// compiled, instead of making every action that may cause the consequence
// CANNOT_AUTHORIZE. A fact declared about the consequence's target, and the
// same fact read by a rule on a dispatched operation, compile. Without the
// subject types (the Authority's own compile) nothing is refused.
func TestHR206_ARuleOnAConsequenceReadsOnlyFactsAboutItsTarget(t *testing.T) {
	f := newFixture(t)
	payout := *f.def("payments.refund.create")
	payout.Operation, payout.Mappings, payout.Digest = "payments.payout.trigger", nil, "sha256:payout"
	facts := map[string]fdomain.Type{"payments.charge.held": fdomain.TypeBoolean, "github.pull.head": fdomain.TypeObject}
	subjects := map[string]string{"payments.charge.held": "payments.charge", "github.pull.head": "github.pull_request"}
	rule := func(op, fact, when string) domain.Rule {
		return domain.Rule{
			ID: "r", Kind: domain.Forbid, Summary: "x", Operations: []string{op}, When: when, Reason: "NOPE",
			Facts: []domain.FactRef{{Name: fact, MaxAgeSeconds: 30}},
		}
	}
	compile := func(r domain.Rule, subjects map[string]string) error {
		e := &Engine{Limits: celenv.DefaultLimits, Facts: facts, Subjects: subjects}
		_, err := e.Compile(&domain.Bundle{ID: "test", Version: 1, Rules: []domain.Rule{r}}, []*defs.Definition{&payout, f.def("payments.refund.create")})
		return err
	}
	if err := compile(rule("payments.payout.trigger", "github.pull.head", "facts.github_pull_head.draft == true"), subjects); err == nil ||
		!strings.Contains(err.Error(), `fact "github.pull.head" is declared about a github.pull_request`) {
		t.Fatalf("a fact about another subject: %v", err)
	}
	for name, err := range map[string]error{
		"a fact about the consequence's target": compile(rule("payments.payout.trigger", "payments.charge.held", "facts.payments_charge_held"), subjects),
		"the fact on a dispatched operation":    compile(rule("payments.refund.create", "github.pull.head", "facts.github_pull_head.draft == true"), subjects),
		"the Authority's compile":               compile(rule("payments.payout.trigger", "github.pull.head", "facts.github_pull_head.draft == true"), nil),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
