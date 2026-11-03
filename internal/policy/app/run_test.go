// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestPolicySeesTheRun (G0 M8 C4): a rule reads `run.id` and
// `run.agent_id` from the input's run; without a run both are "".
func TestPolicySeesTheRun(t *testing.T) {
	f := newFixture(t)
	c, err := f.compile(refundRule("agent", domain.Forbid, `run.agent_id == "a1" && run.id == "r1"`))
	if err != nil {
		t.Fatal(err)
	}
	a := f.refund("30.00", "duplicate")
	for _, tc := range []struct {
		run  *Run
		want domain.Verdict
	}{
		{&Run{ID: "r1", AgentID: "a1"}, domain.VerdictDeny},
		{&Run{ID: "r1", AgentID: "a2"}, domain.VerdictPass},
		{&Run{ID: "r2", AgentID: "a1"}, domain.VerdictPass},
		{nil, domain.VerdictPass},
	} {
		out, err := c.Evaluate(context.Background(), f.def(a.Operation), a, Input{Budget: 10_000, Run: tc.run})
		if err != nil {
			t.Fatal(err)
		}
		if out.Verdict != tc.want {
			t.Errorf("run %+v: %s, want %s", tc.run, out.Verdict, tc.want)
		}
	}
	if _, err := f.compile(refundRule("bad", domain.Forbid, `run.instance_id == ""`)); err == nil {
		t.Fatal("a rule compiled with a run field that does not exist")
	}
}

// TestHR648_ARuleMayDenyOnContentFlags (G0 M27 D512): an org's rule reads
// `run.content_flags`; without a run or a flag the list is empty and the rule
// passes.
//
// Covers: F939
func TestHR648_ARuleMayDenyOnContentFlags(t *testing.T) {
	f := newFixture(t)
	c, err := f.compile(refundRule("flagged", domain.Forbid, `"injection_phrase" in run.content_flags`))
	if err != nil {
		t.Fatal(err)
	}
	a := f.refund("30.00", "duplicate")
	for _, tc := range []struct {
		run  *Run
		want domain.Verdict
	}{
		{&Run{ID: "r1", ContentFlags: []string{"injection_phrase"}}, domain.VerdictDeny},
		{&Run{ID: "r1", ContentFlags: []string{"pii_email"}}, domain.VerdictPass},
		{&Run{ID: "r1"}, domain.VerdictPass},
		{nil, domain.VerdictPass},
	} {
		out, err := c.Evaluate(context.Background(), f.def(a.Operation), a, Input{Budget: 10_000, Run: tc.run})
		if err != nil {
			t.Fatal(err)
		}
		if out.Verdict != tc.want {
			t.Errorf("run %+v: %s, want %s", tc.run, out.Verdict, tc.want)
		}
	}
}

// TestReadsRunConsequencesScansEveryCELSite (G0 M17 D103, D141): the
// Authority reads the run's consequence counts only for a bundle that
// ReadsRunConsequences says uses them, so a count referenced in any CEL
// expression the compiler compiles must be found there; read as 0 it
// would fail open. Each site kind below holds a reference in turn, and the
// list of kinds must match what celExpressions returns, so a new site
// fails this test until it is listed.
//
// Covers: F414
func TestReadsRunConsequencesScansEveryCELSite(t *testing.T) {
	sites := map[string]func(r *domain.Rule, expr string){
		"when": func(r *domain.Rule, expr string) { r.When = expr },
	}
	if n := len(celExpressions(&domain.Rule{})); n != len(sites) {
		t.Fatalf("celExpressions returns %d sites, the test knows %d: add the new one", n, len(sites))
	}
	for name, set := range sites {
		for _, field := range []string{"run.consequences_pending", "run.consequences_unconfirmed"} {
			r := domain.Rule{ID: "r", When: "true"}
			set(&r, field+" > 0")
			if !ReadsRunConsequences(&domain.Bundle{Rules: []domain.Rule{{ID: "other", When: "true"}, r}}) {
				t.Errorf("%s in %s: not read", field, name)
			}
		}
	}
	for _, b := range []*domain.Bundle{nil, {}, {Rules: []domain.Rule{{ID: "r", When: `run.agent_id == "a"`}}}} {
		if ReadsRunConsequences(b) {
			t.Errorf("%+v: read without a reference", b)
		}
	}
}
