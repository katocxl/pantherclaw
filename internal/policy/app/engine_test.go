// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

var tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

// extraParams adds an optional text note, and an optional integer batch
// whose count_max the tool can clamp, to the refund definition.
const extraParams = `      note:
        type: text
      batch:
        type: integer
        unit: count
    effects:`

type fixture struct {
	t      *testing.T
	pkg    *defs.Package
	mapper *mapping.Mapper
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("    effects:"), []byte(extraParams), 1)
	raw = bytes.Replace(raw, []byte("      - kind: amount_max\n        param: amount\n"),
		[]byte("      - kind: amount_max\n        param: amount\n      - kind: count_max\n        param: batch\n        clamp: true\n"), 1)
	p, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, pkg: p, mapper: m}
}

func (f *fixture) def(op string) *defs.Definition {
	d, ok := f.pkg.Definition(op)
	if !ok {
		f.t.Fatalf("no definition %s", op)
	}
	return d
}

func (f *fixture) refund(amount, reason string) actionir.ActionIR {
	f.t.Helper()
	p, err := f.mapper.MCP(context.Background(), tc, "create_refund",
		[]byte(`{"charge":"ch_1","amount":"`+amount+`","currency":"USD","reason":"`+reason+`"}`))
	if err != nil {
		f.t.Fatal(err)
	}
	return p.Action
}

func (f *fixture) compile(rules ...domain.Rule) (*Compiled, error) {
	e := &Engine{Limits: celenv.DefaultLimits}
	return e.Compile(&domain.Bundle{ID: "test", Version: 1, Rules: rules}, []*defs.Definition{f.def("payments.refund.create")})
}

func (f *fixture) eval(c *Compiled, a actionir.ActionIR, budget uint64) domain.Outcome {
	f.t.Helper()
	out, err := c.Evaluate(context.Background(), f.def(a.Operation), a, Input{Budget: budget})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func refundRule(id string, k domain.Kind, when string) domain.Rule {
	r := domain.Rule{ID: id, Kind: k, Summary: id, Operations: []string{"payments.refund.create"}, When: when, Reason: "R_" + string(k)}
	switch k { //nolint:exhaustive // FORBID and CONSTRAIN are set by the callers
	case domain.RequireApproval:
		r.Approval = &domain.ApprovalRequirement{Role: "approver", Count: 1}
	case domain.RequireStepUp:
		r.StepUp = &domain.StepUpRequirement{Subject: "launcher", Method: "webauthn"}
	case domain.Annotate:
		r.Labels = map[string]string{"risk": "high"}
	}
	return r
}

// referenceRules is a refund policy whose every comparison is pinned by the
// scenarios below (see TestHR044_ReferenceRulesKillEveryMutant).
func referenceRules() []domain.Rule {
	limit := refundRule("refund-cap", domain.Constrain, "true")
	limit.Constraint = &domain.Constraint{Kind: domain.AmountMax, Param: "amount", Max: "2000.00", Currency: "USD"}
	return []domain.Rule{
		refundRule("no-large-refunds", domain.Forbid, `action.params.amount > money("1000.00", "USD")`),
		refundRule("approve-over-50", domain.RequireApproval, `action.params.amount > money("50.00", "USD")`),
		refundRule("step-up-fraud", domain.RequireStepUp, `action.params.reason == "fraudulent"`),
		refundRule("flag-500", domain.Annotate, `action.params.amount >= money("500.00", "USD")`),
		limit,
	}
}

type scenario struct {
	amount, reason string
	want           domain.Verdict
	labeled        bool
}

var scenarios = []scenario{
	{"30.00", "duplicate", domain.VerdictPass, false},
	{"50.00", "duplicate", domain.VerdictPass, false},
	{"50.01", "duplicate", domain.VerdictRequireApproval, false},
	{"30.00", "fraudulent", domain.VerdictRequireStepUp, false},
	{"85.00", "fraudulent", domain.VerdictRequireApproval, false},
	{"499.99", "duplicate", domain.VerdictRequireApproval, false},
	{"500.00", "duplicate", domain.VerdictRequireApproval, true},
	{"1000.00", "duplicate", domain.VerdictRequireApproval, true},
	{"1000.01", "duplicate", domain.VerdictDeny, true},
}

func (f *fixture) failures(rules []domain.Rule) []string {
	c, err := f.compile(rules...)
	if err != nil {
		f.t.Fatal(err)
	}
	var bad []string
	for _, s := range scenarios {
		out := f.eval(c, f.refund(s.amount, s.reason), DefaultBudget)
		if out.Verdict != s.want || (out.Labels["risk"] == "high") != s.labeled {
			bad = append(bad, s.amount+"/"+s.reason+" → "+string(out.Verdict))
		}
	}
	return bad
}

func TestReferencePolicyScenarios(t *testing.T) {
	f := newFixture(t)
	if bad := f.failures(referenceRules()); len(bad) > 0 {
		t.Fatalf("scenarios failed: %v", bad)
	}
	c, _ := f.compile(referenceRules()...)
	out := f.eval(c, f.refund("85.00", "fraudulent"), DefaultBudget)
	if len(out.Approvals) != 1 || len(out.StepUps) != 1 {
		t.Fatalf("approval and step-up are both required and tracked separately (F071): %+v", out)
	}
	if d, _ := out.Decisive(); d.Rule != "approve-over-50" {
		t.Fatalf("decisive item: %+v", out.Checklist)
	}
}

// TestHR044_ReferenceRulesKillEveryMutant flips each comparison of each
// rule in turn; some scenario must notice every flip.
func TestHR044_ReferenceRulesKillEveryMutant(t *testing.T) {
	f := newFixture(t)
	for i, r := range referenceRules() {
		mutants, err := Mutants(r.When)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d mutants %q", r.ID, len(mutants), mutants)
		for _, m := range mutants {
			rules := referenceRules()
			rules[i].When = m
			if len(f.failures(rules)) == 0 {
				t.Errorf("mutant of %s survived: %s", r.ID, m)
			}
		}
	}
}

func TestMutants(t *testing.T) {
	got, err := Mutants(`a < 1 && (b == 2 || c >= 3)`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`a <= 1 && (b == 2 || c >= 3)`, `a < 1 && (b != 2 || c >= 3)`, `a < 1 && (b == 2 || c > 3)`}
	if !slices.Equal(got, want) {
		t.Fatalf("Mutants = %q, want %q", got, want)
	}
	if _, err := Mutants(`a <`); err == nil {
		t.Fatal("unparsable condition")
	}
}

func TestHR040_RuntimeErrorsFailClosed(t *testing.T) {
	f := newFixture(t)
	eur := `action.params.amount > money("10.00", "EUR")` // USD amounts make this an error, not false
	badCap := refundRule("cap-eur", domain.Constrain, "true")
	badCap.Constraint = &domain.Constraint{Kind: domain.AmountMax, Param: "amount", Max: "10.00", Currency: "EUR"}
	for name, c := range map[string]struct {
		rule domain.Rule
		want domain.Verdict
	}{
		"forbid":                      {refundRule("f", domain.Forbid, eur), domain.VerdictDeny},
		"approval":                    {refundRule("a", domain.RequireApproval, eur), domain.VerdictCannotAuthorize},
		"step-up":                     {refundRule("s", domain.RequireStepUp, eur), domain.VerdictCannotAuthorize},
		"annotate":                    {refundRule("n", domain.Annotate, eur), domain.VerdictPass},
		"constrain currency mismatch": {badCap, domain.VerdictCannotAuthorize},
	} {
		comp, err := f.compile(c.rule)
		if err != nil {
			t.Fatal(err)
		}
		out := f.eval(comp, f.refund("30.00", "duplicate"), DefaultBudget)
		if out.Verdict != c.want || out.Checklist[0].Status != domain.StatusError {
			t.Errorf("%s: %s %+v, want %s with the error visible", name, out.Verdict, out.Checklist[0], c.want)
		}
	}
}

func TestHR041_PublicationRejectsUnsafeComparisons(t *testing.T) {
	f := newFixture(t)
	for _, when := range []string{
		`action.params.reason > "a"`,
		`action.params.amount > 50`,
		`action.params.amount.amount() > decimal("50") || 1.5 > 1.0`,
		`action.target.id < "ch_5"`,
	} {
		if _, err := f.compile(refundRule("r", domain.Forbid, when)); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", when, err)
		}
	}
}

func TestHR042_PublicationRequiresHasGuards(t *testing.T) {
	f := newFixture(t)
	if _, err := f.compile(refundRule("r", domain.Forbid, `action.params.batch > 10`)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("unguarded optional param: %v", err)
	}
	c, err := f.compile(refundRule("r", domain.Forbid, `has(action.params.batch) && action.params.batch > 10`))
	if err != nil {
		t.Fatal(err)
	}
	if out := f.eval(c, f.refund("30.00", "duplicate"), DefaultBudget); out.Verdict != domain.VerdictPass {
		t.Fatalf("absent optional param: %s", out.Verdict)
	}
}

func TestHR023_TextIsInvisibleToPolicy(t *testing.T) {
	f := newFixture(t)
	for _, when := range []string{`action.params.note == "urgent"`, `has(action.params.note)`} {
		if _, err := f.compile(refundRule("r", domain.Forbid, when)); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid (text params are not in the policy schema)", when, err)
		}
	}
}

func TestHR043_TenantBudgetIsEnforced(t *testing.T) {
	f := newFixture(t)
	c, _ := f.compile(referenceRules()...)
	a := f.refund("30.00", "duplicate")
	for _, budget := range []uint64{0, 1} {
		out := f.eval(c, a, budget)
		if out.Verdict != domain.VerdictCannotAuthorize {
			t.Errorf("budget %d: %s, want CANNOT_AUTHORIZE", budget, out.Verdict)
		}
		if d, _ := out.Decisive(); d.Reason != domain.ReasonCostExceeded {
			t.Errorf("budget %d: decisive %+v", budget, d)
		}
	}
	if out := f.eval(c, a, DefaultBudget); out.Verdict != domain.VerdictPass {
		t.Fatalf("default budget: %s", out.Verdict)
	}
}

func TestConstraintsNeedDeclaredSupport(t *testing.T) {
	f := newFixture(t)
	for name, cons := range map[string]domain.Constraint{
		"target set": {Kind: domain.TargetSet, Values: []string{"ch_1"}},
		"reason":     {Kind: domain.AllowedValues, Param: "reason", Values: []string{"duplicate"}},
	} {
		r := refundRule("c", domain.Constrain, "true")
		r.Constraint = &cons
		c, _ := f.compile(r)
		out := f.eval(c, f.refund("30.00", "duplicate"), DefaultBudget)
		if d, _ := out.Decisive(); out.Verdict != domain.VerdictCannotAuthorize || d.Reason != domain.ReasonUnsupportedObligation {
			t.Errorf("%s: %s %+v, want CANNOT_AUTHORIZE (F100)", name, out.Verdict, d)
		}
	}
}

func TestCountMaxClampsOnlyWhenDeclared(t *testing.T) {
	f := newFixture(t)
	r := refundRule("batch-cap", domain.Constrain, "true")
	r.Constraint = &domain.Constraint{Kind: domain.CountMax, Param: "batch", Max: "10"}
	c, _ := f.compile(r)
	out := f.eval(c, f.refund("30.00", "duplicate"), DefaultBudget)
	if out.Verdict != domain.VerdictConstrain || len(out.Obligations) != 1 || !out.Obligations[0].Clamp ||
		out.Obligations[0].Timing != "before_execution" {
		t.Fatalf("an absent batch must be clamped before execution: %+v", out)
	}
}

// TestHR191_AVerifyRuleRaisesTheRequiredLevel: a matched verify rule needs
// no declared support from the definition: it is an obligation with its
// level, applied after dispatch (step 8 decides whether the verifier can
// reach it); an unmatched one adds nothing, and an unknown level is
// refused when the bundle compiles.
func TestHR191_AVerifyRuleRaisesTheRequiredLevel(t *testing.T) {
	f := newFixture(t)
	r := refundRule("verify-large", domain.Constrain, `action.params.amount > money("50.00", "USD")`)
	r.Constraint = &domain.Constraint{Kind: domain.Verify, Level: defs.LevelFollowUp}
	c, err := f.compile(r)
	if err != nil {
		t.Fatal(err)
	}
	out := f.eval(c, f.refund("80.00", "duplicate"), DefaultBudget)
	if out.Verdict != domain.VerdictConstrain || len(out.Obligations) != 1 {
		t.Fatalf("a large refund: %+v", out)
	}
	if o := out.Obligations[0]; o.Kind != domain.Verify || o.Level != defs.LevelFollowUp || o.Timing != domain.TimingAfterDispatch ||
		o.Rule != "verify-large" || o.Clamp || !o.ByAuthority() {
		t.Fatalf("obligation %+v", o)
	}
	if d, _ := out.Decisive(); d.Status != domain.StatusConstrained || d.Detail != "the effect must be verified at follow_up level" {
		t.Fatalf("checklist %+v", out.Checklist)
	}
	if out := f.eval(c, f.refund("30.00", "duplicate"), DefaultBudget); out.Verdict != domain.VerdictPass || len(out.Obligations) != 0 {
		t.Fatalf("a small refund: %+v", out)
	}
	r.Constraint.Level = "settled"
	if _, err := f.compile(r); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("an unknown level compiled: %v", err)
	}
}

func TestDefinitionsCompiledLaterFailClosed(t *testing.T) {
	f := newFixture(t)
	wide := []domain.Rule{
		refundRule("f", domain.Forbid, `action.params.amount > money("1.00", "USD")`),
		refundRule("a", domain.RequireApproval, `action.params.amount > money("1.00", "USD")`),
	}
	for i := range wide {
		wide[i].Operations = []string{"payments.*"}
	}
	c, err := f.compile(wide...)
	if err != nil {
		t.Fatal(err)
	}
	// payments.refund.get was not compiled for and has no amount param.
	read, err := f.mapper.MCP(context.Background(), tc, "get_refund", []byte(`{"refund":"re_1"}`))
	if err != nil {
		t.Fatal(err)
	}
	out := f.eval(c, read.Action, DefaultBudget)
	if out.Verdict != domain.VerdictDeny {
		t.Fatalf("a FORBID rule that cannot compile for a new definition denies: %+v", out)
	}
	statuses := map[string]domain.Status{}
	for _, it := range out.Checklist {
		statuses[it.Rule] = it.Status
	}
	if !maps.Equal(statuses, map[string]domain.Status{"f": domain.StatusError, "a": domain.StatusError}) {
		t.Fatalf("checklist %+v", out.Checklist)
	}
	if _, err := c.Evaluate(context.Background(), f.def("payments.refund.create"), read.Action, Input{Budget: DefaultBudget}); !errors.Is(err, actionir.ErrAmbiguous) {
		t.Fatalf("an action evaluated against another definition: %v", err)
	}
}

// TestMutationTestingDetectsWeakScenarios is the negative control: without
// the boundary scenario at exactly 50.00, the > → >= mutant survives.
func TestMutationTestingDetectsWeakScenarios(t *testing.T) {
	f := newFixture(t)
	saved := scenarios
	t.Cleanup(func() { scenarios = saved })
	scenarios = slices.DeleteFunc(slices.Clone(saved), func(s scenario) bool { return s.amount == "50.00" })
	rules := referenceRules()
	mutants, err := Mutants(rules[1].When)
	if err != nil {
		t.Fatal(err)
	}
	rules[1].When = mutants[0]
	if bad := f.failures(rules); len(bad) != 0 {
		t.Fatalf("without the boundary scenario the mutant should survive, but it was killed by %v", bad)
	}
}
