// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestRunVariableIsTheServersRecord (G0 M8 C4): policy rules see the
// action's run as `run`, filled from the server's run record, so a rule can
// be scoped to one agent. Nothing in the request sets it: a request naming
// another agent's run is refused before policy, and the action's own
// fields, whatever they say, never reach it.
func TestRunVariableIsTheServersRecord(t *testing.T) {
	f := newFx(t)
	if err := f.w.SetPolicy([]pdomain.Rule{{
		ID: "agent-only", Kind: pdomain.Forbid, Summary: "this agent may not refund",
		Operations: []string{"payments.refund.create"}, When: `run.agent_id == "` + f.agent.String() + `" && run.id == "` + f.run.String() + `"`,
		Reason: "AGENT_MAY_NOT_REFUND",
	}}, nil); err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, "AGENT_MAY_NOT_REFUND")

	// Another agent, on its own run, is not this rule's.
	other := ids.NewV7()
	f.w.AddAgent(other, pipeline.Agent{State: "VERIFIED", TeamID: f.team, BusinessUnitID: ids.NewV7()})
	grant := f.newGrant(grantBounds)
	grant.AgentID = other
	f.w.Grants.Put(grant)
	run := ids.NewV7()
	f.w.AddRun(run, pipeline.Run{AgentID: other, Launcher: f.alice, Principal: f.alice, EnvironmentID: f.env, GrantID: grant.ID, Active: true})
	req := f.parse(run, ids.NewV7(), "create_refund", refund("ch_1", "30.00"))
	req.Identity.AgentID = other
	if ev := f.eval(req); ev.Decision == adomain.Deny {
		t.Fatalf("another agent's refund: %s %+v", ev.Decision, ev.Decisive())
	}

	// The other agent cannot borrow the first agent's run to look like it,
	// nor the first agent the other's run to escape the rule.
	req = f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "30.00"))
	req.Identity.AgentID = other
	expect(t, f.eval(req), adomain.Deny, pipeline.ReasonRunMismatch)
	req = f.parse(run, ids.NewV7(), "create_refund", refund("ch_1", "30.00"))
	expect(t, f.eval(req), adomain.Deny, pipeline.ReasonRunMismatch)
}
