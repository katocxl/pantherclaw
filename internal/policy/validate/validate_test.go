// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package validate

import (
	"context"
	"encoding/json/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

var testOrg = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000a1")

type world struct {
	defs      []*defs.Definition
	catalog   map[string]fdomain.Type
	approvers int
	supplied  map[string]bool
}

func (w *world) ActiveDefinitions(context.Context, ids.OrgID) ([]*defs.Definition, error) {
	return w.defs, nil
}

func (w *world) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return w.catalog, nil
}

func (w *world) FactSubjects(context.Context, ids.OrgID) (map[string]string, error) {
	return map[string]string{"payments.charge.refundable": "payments.charge"}, nil
}

func (w *world) Approvers(context.Context, ids.OrgID, string) (int, error) { return w.approvers, nil }

func (w *world) SuppliedFacts(context.Context, ids.OrgID) (map[string]bool, error) {
	return w.supplied, nil
}

func newValidator(t *testing.T) (*Validator, *world) {
	t.Helper()
	raw, err := os.ReadFile(pipelinetest.PackagePath())
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{catalog: map[string]fdomain.Type{
		"payments.charge.refundable": fdomain.TypeBoolean, "payments.charge.risk": fdomain.TypeInteger,
	}, approvers: 1, supplied: map[string]bool{"payments.charge.refundable": true, "payments.charge.risk": true}}
	for i := range pkg.Definitions {
		w.defs = append(w.defs, &pkg.Definitions[i])
	}
	v := New(w, w, w, celenv.DefaultLimits)
	v.Approvers, v.Sources = w, w
	v.now = func() time.Time { return pipelinetest.Start }
	return v, w
}

const refund = "payments.refund.create"

func rule(id string, k pdomain.Kind, when string) pdomain.Rule {
	r := pdomain.Rule{ID: id, Kind: k, Summary: "rule " + id, Operations: []string{refund}, When: when, Reason: strings.ToUpper(strings.ReplaceAll(id, "-", "_"))}
	switch k { //nolint:exhaustive // FORBID carries nothing
	case pdomain.RequireApproval:
		r.Approval = &pdomain.ApprovalRequirement{Role: "approver", Count: 1}
	case pdomain.Constrain:
		r.Constraint = &pdomain.Constraint{Kind: pdomain.AmountMax, Param: "amount", Max: "100.00", Currency: "USD"}
	case pdomain.Annotate:
		r.Labels = map[string]string{"risk": "low"}
	}
	return r
}

func over(amount string) pdomain.Rule {
	return rule("approve-over", pdomain.RequireApproval, `action.params.amount > money("`+amount+`", "USD")`)
}

func bundle(rules ...pdomain.Rule) *pdomain.Bundle {
	return &pdomain.Bundle{ID: "refunds", Version: 2, Rules: rules}
}

func validate(t *testing.T, v *Validator, b *pdomain.Bundle) pdomain.ValidationResult {
	t.Helper()
	res, err := v.Validate(context.Background(), testOrg, b)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func codes(res pdomain.ValidationResult) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Severity+" "+f.Code)
	}
	return out
}

func TestValidateCleanBundle(t *testing.T) {
	v, w := newValidator(t)
	res := validate(t, v, bundle(over("50.00")))
	if !res.Passed || len(res.Findings) != 0 {
		t.Fatalf("clean bundle: %v", codes(res))
	}
	if res.DefinitionsDigest != pdomain.DefinitionsDigest(w.defs) || res.CatalogDigest != pdomain.CatalogDigest(w.catalog) {
		t.Fatal("digests are not the inputs'")
	}
}

func TestValidateFindings(t *testing.T) {
	v, w := newValidator(t)
	usd := rule("cap-usd", pdomain.Constrain, "true")
	eur := rule("cap-eur", pdomain.Constrain, "true")
	eur.Constraint.Currency = "EUR"
	verify := rule("verify-deep", pdomain.Constrain, "true")
	verify.Constraint = &pdomain.Constraint{Kind: pdomain.Verify, Level: defs.LevelDownstream}
	values := rule("reasons", pdomain.Constrain, "true")
	values.Constraint = &pdomain.Constraint{Kind: pdomain.AllowedValues, Param: "reason", Values: []string{"duplicate"}}
	unknownOp := rule("shell", pdomain.Forbid, "true")
	unknownOp.Operations = []string{"shell.exec"}
	unknownFact := rule("risky", pdomain.Forbid, "facts.payments_charge_score > 5")
	unknownFact.Facts = []pdomain.FactRef{{Name: "payments.charge.score", MaxAgeSeconds: 60}}
	loose := rule("cap-loose", pdomain.Constrain, "true")
	loose.Constraint.Max = "500.00"
	for name, c := range map[string]struct {
		b    *pdomain.Bundle
		want []string
	}{
		"operation unknown":      {bundle(over("50.00"), unknownOp), []string{"ERROR OPERATION_UNKNOWN"}},
		"fact unknown":           {bundle(unknownFact), []string{"ERROR FACT_UNKNOWN", "ERROR COMPILE_ERROR"}},
		"constraint unsupported": {bundle(values), []string{"ERROR CONSTRAINT_UNSUPPORTED"}},
		"verify unreachable":     {bundle(verify), []string{"ERROR VERIFY_UNREACHABLE"}},
		"compile error":          {bundle(rule("bad", pdomain.Forbid, "action.params.nope > 1")), []string{"ERROR COMPILE_ERROR"}},
		"conflict":               {bundle(usd, eur), []string{"ERROR CONFLICT"}},
		"shadowed":               {bundle(rule("deny-over-10", pdomain.Forbid, `action.params.amount > money("10.00", "USD")`), over("50.00")), []string{"WARNING SHADOWED"}},
		"not shadowed by later":  {bundle(over("50.00"), rule("deny-over-10", pdomain.Forbid, `action.params.amount > money("10.00", "USD")`)), nil},
		"redundant":              {bundle(usd, loose), []string{"INFO REDUNDANT"}},
	} {
		res := validate(t, v, c.b)
		if got := codes(res); !slices.Equal(got, c.want) {
			t.Errorf("%s: findings %v, want %v", name, got, c.want)
			continue
		}
		wantPass := !slices.ContainsFunc(c.want, func(s string) bool { return strings.HasPrefix(s, "ERROR") })
		if res.Passed != wantPass {
			t.Errorf("%s: passed %v", name, res.Passed)
		}
	}
	res := validate(t, v, bundle(usd, eur))
	f := res.Findings[0]
	if !f.SampleBased || len(f.Example) == 0 || !slices.Equal(f.Rules, []string{"cap-usd", "cap-eur"}) {
		t.Fatalf("conflict finding: %+v", f)
	}
	var ex actionir.ActionIR
	if err := json.Unmarshal(f.Example, &ex); err != nil || ex.Operation != refund {
		t.Fatalf("conflict example %s: %v", f.Example, err)
	}
	res = validate(t, v, bundle(rule("deny-over-10", pdomain.Forbid, `action.params.amount > money("10.00", "USD")`), over("50.00")))
	if f := res.Findings[0]; !f.SampleBased || !slices.Equal(f.Rules, []string{"approve-over", "deny-over-10"}) {
		t.Fatalf("shadowed finding: %+v", f)
	}
	if res := validate(t, v, bundle(usd, loose)); res.Findings[0].Rules[0] != "cap-loose" {
		t.Fatalf("redundant names %v", res.Findings[0].Rules)
	}

	w.approvers = 0
	risky := over("50.00")
	risky.Facts = []pdomain.FactRef{{Name: "payments.charge.risk", MaxAgeSeconds: 60}}
	delete(w.supplied, "payments.charge.risk")
	if got := codes(validate(t, v, bundle(risky))); !slices.Equal(got, []string{"WARNING APPROVER_NONE", "WARNING FACT_NO_SOURCE"}) {
		t.Fatalf("optional checks: %v", got)
	}
	v.Approvers, v.Sources = nil, nil
	if got := codes(validate(t, v, bundle(risky))); len(got) != 0 {
		t.Fatalf("without ports: %v", got)
	}
}

// TestHR238_ValidationSamplesAreBounded: however many literals the rules
// hold, at most 256 samples per operation and 4 096 per run are evaluated.
func TestHR238_ValidationSamplesAreBounded(t *testing.T) {
	v, w := newValidator(t)
	var rules []pdomain.Rule
	for i := range 200 {
		r := over(strconv.Itoa(100+i) + ".00")
		r.ID = "over-" + strconv.Itoa(i)
		rules = append(rules, r)
	}
	g := &generator{lit: collect(rules), catalog: w.catalog, now: pipelinetest.Start, budget: 1}
	var create *defs.Definition
	for _, d := range w.defs {
		if d.Operation == refund {
			create = d
		}
	}
	if n := len(g.samples(create, nil)); n != MaxSamplesPerOperation {
		t.Fatalf("%d samples for one operation, want %d", n, MaxSamplesPerOperation)
	}
	g.total = MaxSamples - 3
	if n := len(g.samples(create, nil)); n != 3 {
		t.Fatalf("%d samples past the run cap", n)
	}
	// Boundaries: 49.99, 50.00 and 50.01 around a 50.00 threshold.
	g = &generator{lit: collect([]pdomain.Rule{over("50")}), catalog: w.catalog, now: pipelinetest.Start, budget: 1}
	var amounts []string
	for _, s := range g.samples(create, nil) {
		var p struct {
			Amount struct {
				Value string `json:"value"`
			} `json:"amount"`
		}
		if err := json.Unmarshal(s.action.Params, &p); err == nil {
			amounts = append(amounts, p.Amount.Value)
		}
	}
	for _, a := range []string{"49.99", "50.00", "50.01"} {
		if !slices.Contains(amounts, a) {
			t.Errorf("no sample at %s: %v", a, amounts)
		}
	}
	if res := validate(t, v, bundle(rules...)); !res.Passed {
		t.Fatalf("a large clean bundle: %v", codes(res))
	}
	// Samples run under the tenant CEL budget (D26): with a budget of 1
	// every condition runs out, so nothing matches and no shadow is found.
	if v.Budget != papp.DefaultBudget {
		t.Fatalf("default sample budget %d", v.Budget)
	}
	shadowed := bundle(rule("deny-over-10", pdomain.Forbid, `action.params.amount > money("10.00", "USD")`), over("50.00"))
	if got := codes(validate(t, v, shadowed)); !slices.Equal(got, []string{"WARNING SHADOWED"}) {
		t.Fatalf("default budget: %v", got)
	}
	v.Budget = 1
	if got := codes(validate(t, v, shadowed)); len(got) != 0 {
		t.Fatalf("budget 1: %v", got)
	}
}

func TestOutcomeDiff(t *testing.T) {
	v, _ := newValidator(t)
	ctx := context.Background()
	diff := func(base, next *pdomain.Bundle) []OutcomeChange {
		t.Helper()
		out, err := v.OutcomeDiff(ctx, testOrg, base, next)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	categories := func(out []OutcomeChange) []replay.Category {
		var cs []replay.Category
		for _, c := range out {
			if !slices.Contains(cs, c.Category) {
				cs = append(cs, c.Category)
			}
		}
		return cs
	}
	looser := diff(bundle(over("50.00")), bundle(over("100.00")))
	if got := categories(looser); !slices.Equal(got, []replay.Category{replay.NewlyAllowed}) {
		t.Fatalf("raising the threshold: %v", got)
	}
	var amounts []string
	for _, c := range looser {
		var a actionir.ActionIR
		if err := json.Unmarshal(c.Example, &a); err != nil {
			t.Fatal(err)
		}
		amounts = append(amounts, string(a.Params))
		if c.BeforeDecision != "REQUIRE_APPROVAL" || c.AfterDecision != "ALLOW" || c.BeforeReason != "APPROVE_OVER" || c.Operation != refund {
			t.Fatalf("change %+v", c)
		}
	}
	if !slices.ContainsFunc(amounts, func(s string) bool { return strings.Contains(s, `"50.01"`) }) ||
		slices.ContainsFunc(amounts, func(s string) bool { return strings.Contains(s, `"100.01"`) }) {
		t.Fatalf("changed samples %v", amounts)
	}
	if got := categories(diff(bundle(over("100.00")), bundle(over("50.00")))); !slices.Equal(got, []replay.Category{replay.NewlyHeld}) {
		t.Fatalf("lowering the threshold: %v", got)
	}
	if got := categories(diff(nil, bundle(rule("no-refunds", pdomain.Forbid, "true")))); !slices.Equal(got, []replay.Category{replay.NewlyDenied}) {
		t.Fatalf("from no policy: %v", got)
	}
	if out := diff(bundle(over("50.00")), bundle(over("50.00"))); len(out) != 0 {
		t.Fatalf("same version: %+v", out)
	}
	if _, err := v.OutcomeDiff(ctx, testOrg, nil, bundle(rule("bad", pdomain.Forbid, "action.params.nope > 1"))); err == nil {
		t.Fatal("an uncompilable version was diffed")
	}
}
