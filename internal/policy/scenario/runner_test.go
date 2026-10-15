// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scenario

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

var testOrg = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000a1")

// world is the read side the runner gets: the mock-payments definitions
// and a catalog, counting every read (HR-232).
type world struct {
	defs    []*defs.Definition
	catalog map[string]fdomain.Type
	reads   []string
	fail    bool
}

func (w *world) ActiveDefinitions(_ context.Context, org ids.OrgID) ([]*defs.Definition, error) {
	w.reads = append(w.reads, "definitions:"+org.String())
	if w.fail {
		return nil, errors.New("down")
	}
	return w.defs, nil
}

func (w *world) Catalog(_ context.Context, org ids.OrgID) (map[string]fdomain.Type, error) {
	w.reads = append(w.reads, "catalog:"+org.String())
	return w.catalog, nil
}

func newWorld(t *testing.T) *world {
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
	}}
	for i := range pkg.Definitions {
		w.defs = append(w.defs, &pkg.Definitions[i])
	}
	return w
}

func newRunner(w *world, budget uint64) *Runner {
	r := New(w, w, celenv.DefaultLimits, budget)
	r.now = func() time.Time { return pipelinetest.Start }
	return r
}

const refund = "payments.refund.create"

func refundCase(id, amount string, expect pdomain.TestExpect) pdomain.TestCase {
	return pdomain.TestCase{
		ID: id, Summary: "refund " + amount,
		Action: pdomain.TestAction{
			Operation: refund, Target: &actionir.Target{Type: "payments.charge", ID: "ch_1"},
			Params: jsontext.Value(`{"amount":{"value":"` + amount + `","currency":"USD"},"reason":"duplicate"}`),
		},
		Given:  &pdomain.TestGiven{Facts: map[string]pdomain.TestFact{"payments.charge.refundable": {Value: jsontext.Value(`{"bool":true}`), AgeSeconds: 60}}},
		Expect: expect,
	}
}

func allow() pdomain.TestExpect { return pdomain.TestExpect{Decision: "ALLOW", Reason: "GRANT_COVERS"} }

func held(rule string) pdomain.TestExpect {
	return pdomain.TestExpect{Decision: "REQUIRE_APPROVAL", Reason: "REFUND_OVER_50", Rule: rule}
}

func over50() pdomain.Rule {
	return pdomain.Rule{
		ID: "approve-over-50", Kind: pdomain.RequireApproval, Summary: "refunds over 50 USD need an approver",
		Operations: []string{refund}, When: `action.params.amount > money("50.00", "USD")`,
		Reason: "REFUND_OVER_50", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
}

func bundle(rules []pdomain.Rule, tests ...pdomain.TestCase) *pdomain.Bundle {
	return &pdomain.Bundle{ID: "refunds", Version: 3, Rules: rules, Tests: tests}
}

func runOK(t *testing.T, r *Runner, b *pdomain.Bundle) pdomain.TestResult {
	t.Helper()
	res, err := r.Run(context.Background(), testOrg, b)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestScenarioCasesUseTheRealPipeline(t *testing.T) {
	w := newWorld(t)
	b := bundle([]pdomain.Rule{over50()},
		refundCase("small", "50.00", allow()),
		refundCase("large", "50.01", held("approve-over-50")),
		func() pdomain.TestCase { // the pipeline, not the engine: a missing fact is CANNOT_AUTHORIZE
			c := refundCase("no-fact", "10.00", pdomain.TestExpect{Decision: "CANNOT_AUTHORIZE", Reason: fdomain.ReasonFactMissing})
			c.Given.Facts = nil
			return c
		}(),
		func() pdomain.TestCase {
			c := refundCase("approved", "60.00", allow())
			c.Given.Approval = pdomain.ApprovalApproved
			c.Expect.Reason = "GRANT_COVERS"
			return c
		}(),
		func() pdomain.TestCase {
			c := refundCase("other-approval", "60.00", held(""))
			c.Given.Approval = pdomain.ApprovalApprovedOtherAction
			return c
		}(),
		func() pdomain.TestCase {
			c := refundCase("expired", "60.00", pdomain.TestExpect{Decision: "DENY", Reason: "APPROVAL_EXPIRED"})
			c.Given.Approval = pdomain.ApprovalExpired
			return c
		}(),
		func() pdomain.TestCase { // the grant's own bound decides
			c := refundCase("grant-cap", "30.00", pdomain.TestExpect{Decision: "DENY", Reason: "GRANT_LIMIT_EXCEEDED"})
			c.Given.Grant = &pdomain.TestGrant{Constraints: []pdomain.Constraint{{Kind: pdomain.AmountMax, Param: "amount", Max: "20.00", Currency: "USD"}}}
			return c
		}(),
		func() pdomain.TestCase {
			c := refundCase("budget", "30.00", pdomain.TestExpect{Decision: "DENY", Reason: "BUDGET_EXHAUSTED"})
			c.Given.Budget = &pdomain.TestBudget{Param: "amount", Currency: "USD", Limit: "100.00", Used: "80.00"}
			return c
		}(),
	)
	res := runOK(t, newRunner(w, papp.DefaultBudget), b)
	for _, c := range res.Cases {
		if !c.Passed {
			t.Errorf("case %s: %s", c.ID, c.Detail)
		}
	}
	if res.Mutants != 2 || res.Survivors != 0 || !res.Passed || res.Error != "" {
		t.Fatalf("gate: %+v", res)
	}
	if res.DefinitionsDigest != pdomain.DefinitionsDigest(w.defs) || res.CatalogDigest != pdomain.CatalogDigest(w.catalog) {
		t.Fatal("result digests are not the inputs'")
	}
}

func TestScenarioCaseFailuresExplain(t *testing.T) {
	w := newWorld(t)
	bad := func(id string, edit func(*pdomain.TestCase)) pdomain.TestCase {
		c := refundCase(id, "10.00", allow())
		edit(&c)
		return c
	}
	b := bundle([]pdomain.Rule{over50()},
		bad("wrong-expect", func(c *pdomain.TestCase) { c.Expect = held("") }),
		bad("bad-agent", func(c *pdomain.TestCase) { c.Given.Agent = "agent-7" }),
		bad("bad-env", func(c *pdomain.TestCase) { c.Action.Environment = "prod" }),
		bad("bad-op", func(c *pdomain.TestCase) { c.Action.Operation = "payments.charge.create" }),
		bad("bad-fact", func(c *pdomain.TestCase) {
			c.Given.Facts["unknown.fact"] = pdomain.TestFact{Value: jsontext.Value(`{"int":"1"}`)}
		}),
		bad("bad-approval", func(c *pdomain.TestCase) { c.Given.Approval = "maybe" }),
		bad("bad-grant", func(c *pdomain.TestCase) {
			c.Given.Grant = &pdomain.TestGrant{Constraints: []pdomain.Constraint{{Kind: pdomain.Verify, Level: defs.LevelDownstream}}}
		}),
	)
	res := runOK(t, newRunner(w, papp.DefaultBudget), b)
	want := map[string]string{
		"wrong-expect": "decided ALLOW GRANT_COVERS, expected REQUIRE_APPROVAL REFUND_OVER_50",
		"bad-agent":    `given.agent "agent-7" is not a canonical UUID`,
		"bad-env":      "not a canonical UUID",
		"bad-op":       "OPERATION_UNKNOWN",
		"bad-fact":     "unknown.fact is not a fact",
		"bad-approval": "given.approval",
		"bad-grant":    "a grant has no",
	}
	if res.Passed {
		t.Fatal("failing cases passed the gate")
	}
	for _, c := range res.Cases {
		if c.Passed || !strings.Contains(c.Detail, want[c.ID]) {
			t.Errorf("case %s: passed=%v detail %q, want %q", c.ID, c.Passed, c.Detail, want[c.ID])
		}
	}
}

// TestHR044_EverySurvivingMutantFailsTheGate: a threshold no case pins, or
// a rule no case needs, refuses the bundle; adding the cases that pin them
// passes it.
func TestHR044_EverySurvivingMutantFailsTheGate(t *testing.T) {
	w := newWorld(t)
	r := newRunner(w, papp.DefaultBudget)
	// Only far-away amounts: the > ↔ >= flip survives.
	weak := runOK(t, r, bundle([]pdomain.Rule{over50()}, refundCase("tiny", "1.00", allow()), refundCase("huge", "500.00", held(""))))
	if weak.Passed || weak.Survivors != 1 || weak.Surviving[0].Rule != "approve-over-50" ||
		!strings.Contains(weak.Surviving[0].Mutation, ">=") {
		t.Fatalf("weak tests: %+v", weak)
	}
	// No case where the rule matters: its removal survives too.
	none := runOK(t, r, bundle([]pdomain.Rule{over50()}, refundCase("tiny", "1.00", allow())))
	if none.Passed || !slices.ContainsFunc(none.Surviving, func(m pdomain.MutantResult) bool { return m.Mutation == RemoveRule }) {
		t.Fatalf("removal survived unnoticed: %+v", none)
	}
	// No tests at all can never pass.
	if empty := runOK(t, r, bundle([]pdomain.Rule{over50()})); empty.Passed || empty.Survivors != 2 {
		t.Fatalf("no tests: %+v", empty)
	}
	strong := runOK(t, r, bundle([]pdomain.Rule{over50()}, refundCase("at", "50.00", allow()), refundCase("above", "50.01", held(""))))
	if !strong.Passed || strong.Survivors != 0 || strong.Mutants != 2 {
		t.Fatalf("boundary tests: %+v", strong)
	}
	// ANNOTATE rules decide nothing and have no mutants.
	ann := pdomain.Rule{
		ID: "tag", Kind: pdomain.Annotate, Summary: "tag refunds", Operations: []string{refund}, When: `action.params.amount > money("1.00", "USD")`,
		Reason: "TAGGED", Labels: map[string]string{"risk": "low"},
	}
	withAnn := runOK(t, r, bundle([]pdomain.Rule{over50(), ann}, refundCase("at", "50.00", allow()), refundCase("above", "50.01", held(""))))
	if !withAnn.Passed || withAnn.Mutants != 2 {
		t.Fatalf("annotation: %+v", withAnn)
	}
}

// TestHR232_ScenarioTestsReadOnlyTheirTwoPorts: a run reads the active
// definitions and the fact catalog once each, and the package cannot reach
// anything that writes: no database, finalization, store or audit import.
func TestHR232_ScenarioTestsReadOnlyTheirTwoPorts(t *testing.T) {
	w := newWorld(t)
	res := runOK(t, newRunner(w, papp.DefaultBudget), bundle([]pdomain.Rule{over50()}, refundCase("at", "50.00", allow()), refundCase("above", "50.01", held(""))))
	if !res.Passed {
		t.Fatalf("%+v", res)
	}
	if want := []string{"definitions:" + testOrg.String(), "catalog:" + testOrg.String()}; !slices.Equal(w.reads, want) {
		t.Fatalf("reads %v, want %v", w.reads, want)
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"/platform/db", "/authority/finalize", "/adapters/", "/audit", "pgx", "database/sql", "net/http", "os/exec"}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range forbidden {
				if strings.Contains(p, bad) {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
	w.fail = true
	if _, err := newRunner(w, papp.DefaultBudget).Run(context.Background(), testOrg, bundle([]pdomain.Rule{over50()})); err == nil {
		t.Fatal("a failed read was not an error")
	}
}

// TestHR238_TestRunsAreBounded: more than 200 cases, more than 20 000
// evaluations, or a condition over the tenant's CEL budget never pass.
func TestHR238_TestRunsAreBounded(t *testing.T) {
	w := newWorld(t)
	r := newRunner(w, papp.DefaultBudget)
	many := make([]pdomain.TestCase, MaxCases+1)
	for i := range many {
		many[i] = refundCase("c"+strconv.Itoa(i), "1.00", allow())
	}
	res := runOK(t, r, bundle([]pdomain.Rule{over50()}, many...))
	if res.Passed || res.Error != pdomain.ErrTestsTooLarge {
		t.Fatalf("201 cases: %+v", res)
	}
	if len(w.reads) != 0 {
		t.Fatal("an oversized run read anything")
	}
	// 200 cases that kill nothing × enough mutants exceeds the evaluation cap.
	var conds []string
	for i := range 60 {
		conds = append(conds, `action.params.amount > money("`+strconv.Itoa(1000+i)+`.00", "USD")`)
	}
	big, big2 := over50(), over50()
	big.When = strings.Join(conds, " && ")
	big2.ID, big2.When = "approve-over-50-again", big.When
	res = runOK(t, r, bundle([]pdomain.Rule{big, big2}, many[:MaxCases]...))
	if res.Passed || res.Error != pdomain.ErrTestsTooLarge {
		t.Fatalf("evaluation cap: passed=%v error=%q mutants=%d", res.Passed, res.Error, res.Mutants)
	}
	// A budget of 1 makes every condition run over: CANNOT_AUTHORIZE, so
	// a case expecting the rule's hold fails.
	tiny := newRunner(w, 1)
	res = runOK(t, tiny, bundle([]pdomain.Rule{over50()}, refundCase("above", "50.01", held(""))))
	if res.Passed || res.Cases[0].Passed || res.Cases[0].Decision != "CANNOT_AUTHORIZE" {
		t.Fatalf("CEL budget: %+v", res)
	}
}

// TestT104_ATestSuiteCannotGameTheGate: cases that expect only what the
// bundle does anyway, or that pin nothing the rules decide, are refused;
// and an invalid bundle is refused before any case runs.
func TestT104_ATestSuiteCannotGameTheGate(t *testing.T) {
	w := newWorld(t)
	r := newRunner(w, papp.DefaultBudget)
	forbid := pdomain.Rule{
		ID: "no-fraud", Kind: pdomain.Forbid, Summary: "no fraud refunds", Operations: []string{refund},
		When: `action.params.reason == "fraudulent"`, Reason: "FRAUD_REFUND",
	}
	// Happy path only: the FORBID's flip denies the happy cases (killed),
	// but its removal changes nothing they show, so it survives.
	happy := runOK(t, r, bundle([]pdomain.Rule{forbid, over50()}, refundCase("ok", "10.00", allow()), refundCase("at", "50.00", allow()),
		refundCase("above", "50.01", held(""))))
	if happy.Passed || !slices.ContainsFunc(happy.Surviving, func(m pdomain.MutantResult) bool { return m.Rule == "no-fraud" }) {
		t.Fatalf("happy path only: %+v", happy)
	}
	// A case's own approval state cannot hide the rule: approved still
	// needs the rule to have asked for it, and the mutant removing the rule
	// is noticed by the unapproved case only.
	approvedOnly := refundCase("approved", "60.00", allow())
	approvedOnly.Given.Approval = pdomain.ApprovalApproved
	res := runOK(t, r, bundle([]pdomain.Rule{over50()}, approvedOnly, refundCase("at", "50.00", allow())))
	if res.Passed {
		t.Fatalf("approved-only cases passed: %+v", res)
	}
	invalid := bundle([]pdomain.Rule{{ID: "x", Kind: pdomain.Forbid, Summary: "x", Operations: []string{refund}, When: "action.params.nope > 1", Reason: "XXX"}},
		refundCase("ok", "1.00", allow()))
	if res := runOK(t, r, invalid); res.Passed || res.Error != ErrBundleInvalid || len(res.Cases) != 0 {
		t.Fatalf("invalid bundle: %+v", res)
	}
}

// TestScenarioAgentScopedRule is D20: a rule on run.agent_id is pinned only
// by a case that gives the agent. The default agent's cases here are all
// denied by the grant's cap, which masks the rule, so neither the == flip
// nor the removal is noticed until a case gives the agent the rule names.
func TestScenarioAgentScopedRule(t *testing.T) {
	w := newWorld(t)
	r := newRunner(w, papp.DefaultBudget)
	agent := "01920000-0000-7000-8000-0000000000b7"
	rule := pdomain.Rule{
		ID: "hold-agent", Kind: pdomain.RequireApproval, Summary: "one agent's refunds need an approver", Operations: []string{refund},
		When: `run.agent_id == "` + agent + `"`, Reason: "AGENT_HELD", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
	capped := refundCase("capped", "30.00", pdomain.TestExpect{Decision: "DENY", Reason: "GRANT_LIMIT_EXCEEDED"})
	capped.Given.Grant = &pdomain.TestGrant{Constraints: []pdomain.Constraint{{Kind: pdomain.AmountMax, Param: "amount", Max: "20.00", Currency: "USD"}}}
	defaults := runOK(t, r, bundle([]pdomain.Rule{rule}, capped))
	if defaults.Passed || defaults.Survivors != 2 || defaults.Surviving[0].Mutation != `run.agent_id != "`+agent+`"` {
		t.Fatalf("default agent only: %+v", defaults)
	}
	named := refundCase("named", "10.00", pdomain.TestExpect{Decision: "REQUIRE_APPROVAL", Reason: "AGENT_HELD", Rule: "hold-agent"})
	named.Given.Agent = agent
	withAgent := runOK(t, r, bundle([]pdomain.Rule{rule}, capped, named))
	if !withAgent.Passed || withAgent.Mutants != 2 {
		t.Fatalf("with given.agent: %+v", withAgent)
	}
	if DefaultAgentID.String() != "00000000-0000-7000-8000-0000000000a1" {
		t.Fatal("the documented default agent id changed")
	}
}
