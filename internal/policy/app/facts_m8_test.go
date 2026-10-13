// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
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
