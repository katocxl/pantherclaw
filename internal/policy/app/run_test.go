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
