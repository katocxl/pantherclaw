// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"slices"
	"strconv"
	"testing"

	"pgregory.net/rapid"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

func rule(id string, k Kind) *Rule {
	r := &Rule{ID: id, Kind: k, Summary: "rule " + id, Operations: []string{"payments.*"}, When: "true", Reason: "REASON_" + string(k)}
	switch k { //nolint:exhaustive // FORBID carries nothing extra
	case RequireApproval:
		r.Approval = &ApprovalRequirement{Role: "approver", Count: 1}
	case RequireStepUp:
		r.StepUp = &StepUpRequirement{Subject: "launcher", Method: "webauthn"}
	case Constrain:
		r.Constraint = &Constraint{Kind: CountMax, Param: "limit", Max: "100"}
	case Annotate:
		r.Labels = map[string]string{"risk": "high"}
	}
	return r
}

func TestBundleValidation(t *testing.T) {
	ok := Bundle{ID: "refunds", Version: 1}
	for i, k := range []Kind{Forbid, RequireApproval, RequireStepUp, Constrain, Annotate} {
		ok.Rules = append(ok.Rules, *rule("r-"+strconv.Itoa(i), k))
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(b *Bundle){
		"no rules":          func(b *Bundle) { b.Rules = nil },
		"version":           func(b *Bundle) { b.Version = 0 },
		"duplicate id":      func(b *Bundle) { b.Rules[1].ID = b.Rules[0].ID },
		"rule id":           func(b *Bundle) { b.Rules[0].ID = "Rule 1" },
		"reason":            func(b *Bundle) { b.Rules[0].Reason = "too big" },
		"summary newline":   func(b *Bundle) { b.Rules[0].Summary = "a\nb" },
		"no condition":      func(b *Bundle) { b.Rules[0].When = "" },
		"no operations":     func(b *Bundle) { b.Rules[0].Operations = nil },
		"wildcard all":      func(b *Bundle) { b.Rules[0].Operations = []string{"*"} },
		"inner wildcard":    func(b *Bundle) { b.Rules[0].Operations = []string{"payments.*.create"} },
		"kind":              func(b *Bundle) { b.Rules[0].Kind = "ALLOW" },
		"forbid + approval": func(b *Bundle) { b.Rules[0].Approval = &ApprovalRequirement{Role: "x", Count: 1} },
		"approval count":    func(b *Bundle) { b.Rules[1].Approval.Count = 3 },
		"step-up subject":   func(b *Bundle) { b.Rules[2].StepUp.Subject = "agent" },
		"constraint kind":   func(b *Bundle) { b.Rules[3].Constraint.Kind = "magic" },
		"constraint no max": func(b *Bundle) { b.Rules[3].Constraint.Max = "" },
		"target set param": func(b *Bundle) {
			b.Rules[3].Constraint = &Constraint{Kind: TargetSet, Param: "x", Values: []string{"a"}}
		},
		"label key":   func(b *Bundle) { b.Rules[4].Labels = map[string]string{"Risk Level": "x"} },
		"environment": func(b *Bundle) { b.Rules[0].Environments = []string{"prod env"} },
	} {
		b := ok
		b.Rules = slices.Clone(ok.Rules)
		for i := range b.Rules { // deep-enough copy of the pointer fields we mutate
			r := &b.Rules[i]
			if r.Approval != nil {
				a := *r.Approval
				r.Approval = &a
			}
			if r.StepUp != nil {
				s := *r.StepUp
				r.StepUp = &s
			}
			if r.Constraint != nil {
				c := *r.Constraint
				r.Constraint = &c
			}
		}
		mutate(&b)
		if err := b.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestRuleScope(t *testing.T) {
	r := rule("a", Forbid)
	r.Operations = []string{"payments.*", "git.merge"}
	r.Environments = []string{"prod"}
	for _, c := range []struct {
		op, env string
		want    bool
	}{
		{"payments.refund.create", "prod", true},
		{"git.merge", "prod", true},
		{"payments.refund.create", "dev", false},
		{"paymentsx.refund", "prod", false},
		{"git.merge.force", "prod", false},
	} {
		if got := r.Applies(c.op, c.env); got != c.want {
			t.Errorf("Applies(%s, %s) = %v", c.op, c.env, got)
		}
	}
}

func verdictOf(rs ...Result) Verdict { return Compose(rs).Verdict }

func TestHR040_RuleErrorsFailClosed(t *testing.T) {
	for k, want := range map[Kind]Verdict{
		Forbid: VerdictDeny, RequireApproval: VerdictCannotAuthorize, RequireStepUp: VerdictCannotAuthorize,
		Constrain: VerdictCannotAuthorize, Annotate: VerdictPass,
	} {
		out := Compose([]Result{{Rule: rule("r", k), Effect: EvalError, Detail: "no such key"}})
		if out.Verdict != want {
			t.Errorf("%s error: %s, want %s", k, out.Verdict, want)
		}
		if out.Checklist[0].Status != StatusError || out.Checklist[0].Reason != ReasonEvalError {
			t.Errorf("%s error must be visible in the checklist: %+v", k, out.Checklist[0])
		}
	}
}

func TestHR043_CostOverrunIsCannotAuthorize(t *testing.T) {
	if v := verdictOf(Result{Rule: rule("f", Forbid), Effect: CostExceeded}); v != VerdictCannotAuthorize {
		t.Fatalf("cost overrun in FORBID: %s", v)
	}
	if v := verdictOf(Result{Rule: rule("a", Forbid), Effect: Matched}, Result{Rule: rule("f", Forbid), Effect: CostExceeded}); v != VerdictDeny {
		t.Fatalf("a matched prohibition still wins: %s", v)
	}
}

func TestCompositionPrecedence(t *testing.T) {
	obl := &Obligation{Rule: "c", Kind: CountMax, Param: "limit", Max: "100", Clamp: true, Timing: "before_execution"}
	out := Compose([]Result{
		{Rule: rule("n", Annotate), Effect: Matched},
		{Rule: rule("c", Constrain), Effect: Matched, Obligation: obl},
		{Rule: rule("s", RequireStepUp), Effect: Matched},
		{Rule: rule("a", RequireApproval), Effect: Matched},
		{Rule: rule("x", Forbid), Effect: NotMatched},
		{Rule: rule("o", Forbid), Effect: OutOfScope},
	})
	if out.Verdict != VerdictRequireApproval || len(out.Approvals) != 1 || len(out.StepUps) != 1 || len(out.Obligations) != 1 || out.Labels["risk"] != "high" {
		t.Fatalf("approval and step-up are tracked separately and both kept (F071): %+v", out)
	}
	if d, ok := out.Decisive(); !ok || d.Rule != "a" {
		t.Fatalf("decisive item first: %+v", out.Checklist)
	}
	if last := out.Checklist[len(out.Checklist)-1]; last.Status != StatusNotApplicable {
		t.Fatalf("not-applicable items come last: %+v", out.Checklist)
	}
	if v := verdictOf(Result{Rule: rule("c", Constrain), Effect: Matched}); v != VerdictPass {
		t.Fatalf("a constraint the action already meets adds no obligation: %s", v)
	}
	if v := verdictOf(Result{Rule: rule("c", Constrain), Effect: Violated}); v != VerdictDeny {
		t.Fatalf("an exceeded, non-clampable limit denies: %s", v)
	}
	if v := verdictOf(Result{Rule: rule("c", Constrain), Effect: Unsupported}); v != VerdictCannotAuthorize {
		t.Fatalf("an unsupported constraint is CANNOT_AUTHORIZE (F100): %s", v)
	}
	if v := verdictOf(); v != VerdictPass {
		t.Fatalf("no rules: %s", v)
	}
}

// TestHR191_VerifyObligationsNeedAKnownLevelAboveAcceptance: a verify
// constraint names a level above the target's acceptance and nothing else;
// an unknown level, acceptance, or a level on another kind is refused at
// publish (G0 M7 design decision 2, F497).
func TestHR191_VerifyObligationsNeedAKnownLevelAboveAcceptance(t *testing.T) {
	verify := func(c Constraint) error {
		r := rule("v", Constrain)
		r.Constraint = &c
		return (&Bundle{ID: "refunds", Version: 1, Rules: []Rule{*r}}).Validate()
	}
	for _, l := range []defs.Level{defs.LevelFollowUp, defs.LevelDomainEffect, defs.LevelDownstream} {
		if err := verify(Constraint{Kind: Verify, Level: l}); err != nil {
			t.Errorf("verify(%s): %v", l, err)
		}
	}
	for name, c := range map[string]Constraint{
		"no level":           {Kind: Verify},
		"an unknown level":   {Kind: Verify, Level: "settled"},
		"acceptance":         {Kind: Verify, Level: defs.LevelAcceptance},
		"a param":            {Kind: Verify, Level: defs.LevelFollowUp, Param: "amount"},
		"a max":              {Kind: Verify, Level: defs.LevelFollowUp, Max: "1"},
		"values":             {Kind: Verify, Level: defs.LevelFollowUp, Values: []string{"a"}},
		"a level on a limit": {Kind: CountMax, Param: "limit", Max: "100", Level: defs.LevelFollowUp},
	} {
		if err := verify(c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// TestHR191_AVerifyObligationIsTheAuthoritys: a matched verify rule is an
// obligation with its level, applied after dispatch by the Authority and
// never by the gateway; it constrains, it does not deny.
func TestHR191_AVerifyObligationIsTheAuthoritys(t *testing.T) {
	r := rule("v", Constrain)
	r.Constraint = &Constraint{Kind: Verify, Level: defs.LevelFollowUp}
	obl := &Obligation{Rule: "v", Kind: Verify, Level: defs.LevelFollowUp, Timing: TimingAfterDispatch}
	out := Compose([]Result{{Rule: r, Effect: Matched, Obligation: obl}})
	if out.Verdict != VerdictConstrain || len(out.Obligations) != 1 || out.Obligations[0].Level != defs.LevelFollowUp ||
		out.Checklist[0].Status != StatusConstrained {
		t.Fatalf("outcome %+v", out)
	}
	if !out.Obligations[0].ByAuthority() || (Obligation{Kind: CountMax, Clamp: true}).ByAuthority() {
		t.Fatal("only verify obligations are the Authority's")
	}
}

// TestPropCompositionNeverWeakens: the verdict is the strictest single
// verdict, independent of order, and adding a result never weakens it.
func TestPropCompositionNeverWeakens(t *testing.T) {
	kinds := []Kind{Forbid, RequireApproval, RequireStepUp, Constrain, Annotate}
	effects := []Effect{OutOfScope, NotMatched, Matched, Violated, Unsupported, EvalError, CostExceeded}
	gen := rapid.Custom(func(t *rapid.T) Result {
		k := rapid.SampledFrom(kinds).Draw(t, "kind")
		e := rapid.SampledFrom(effects).Draw(t, "effect")
		r := Result{Rule: rule("r", k), Effect: e}
		if k == Constrain && e == Matched && rapid.Bool().Draw(t, "obligation") {
			r.Obligation = &Obligation{Kind: CountMax, Timing: "before_execution"}
		}
		return r
	})
	rapid.Check(t, func(t *rapid.T) {
		rs := rapid.SliceOf(gen).Draw(t, "results")
		v := verdictOf(rs...)
		strictest := VerdictPass
		for _, r := range rs {
			if _, rv, _ := classify(r); stricter(rv, strictest) {
				strictest = rv
			}
		}
		if v != strictest {
			t.Fatalf("verdict %s, strictest single verdict %s", v, strictest)
		}
		perm := slices.Clone(rs)
		slices.Reverse(perm)
		if verdictOf(perm...) != v {
			t.Fatal("order changed the verdict")
		}
		extra := gen.Draw(t, "extra")
		if stricter(v, verdictOf(append(rs, extra)...)) {
			t.Fatal("adding a rule weakened the verdict")
		}
	})
}
