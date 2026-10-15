// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func (f *fx) control(scopeType, scopeID, control, op string) {
	f.w.Cont.Controls = []pipeline.Control{{ID: ids.NewV7(), ScopeType: scopeType, ScopeID: scopeID, Control: control, Operation: op}}
}

// TestHR248_ContainmentControlsDenyInTheDecisionPath: a DENY_ALL control
// on the run, the agent, the run's grant, the connection, the target or the
// run's principal denies every action CONTAINED, and a control on another
// subject denies nothing; a DENY_OPERATION control denies only its
// operation.
func TestHR248_ContainmentControlsDenyInTheDecisionPath(t *testing.T) {
	f := newFx(t)
	read := func() *pipeline.Evaluation { return f.call(f.run, "get_refund", `{"refund":"re_1"}`) }
	write := func() *pipeline.Evaluation { return f.call(f.run, "create_refund", refund("ch_1", "10.00")) }
	expect(t, read(), adomain.Allow, pipeline.ReasonGrantCovers)

	for _, c := range []struct{ scope, id string }{
		{pipeline.ControlScopeRun, f.run.String()},
		{pipeline.ControlScopeAgent, f.agent.String()},
		{pipeline.ControlScopeGrant, f.grant.ID.String()},
		{pipeline.ControlScopeConnection, f.conn.String()},
		{pipeline.ControlScopeResource, "payments.refund:re_*"},
		{pipeline.ControlScopePrincipal, f.alice.String()},
	} {
		f.control(c.scope, c.id, pipeline.ControlDenyAll, "")
		expect(t, read(), adomain.Deny, pipeline.ReasonContained)
		if c.scope != pipeline.ControlScopeResource { // the write targets a charge
			expect(t, write(), adomain.Deny, pipeline.ReasonContained)
		}
	}
	for _, c := range []struct{ scope, id string }{
		{pipeline.ControlScopeRun, ids.NewV7().String()},
		{pipeline.ControlScopeAgent, ids.NewV7().String()},
		{pipeline.ControlScopeGrant, ids.NewV7().String()},
		{pipeline.ControlScopeConnection, ids.NewV7().String()},
		{pipeline.ControlScopeResource, "payments.refund:re_2"},
		{pipeline.ControlScopeResource, "payments.charge:ch_*"},
		{pipeline.ControlScopePrincipal, "user:" + ids.NewV7().String()},
	} {
		f.control(c.scope, c.id, pipeline.ControlDenyAll, "")
		expect(t, read(), adomain.Allow, pipeline.ReasonGrantCovers)
	}

	f.control(pipeline.ControlScopeAgent, f.agent.String(), pipeline.ControlDenyOperation, "payments.refund.create")
	expect(t, read(), adomain.Allow, pipeline.ReasonGrantCovers)
	expect(t, write(), adomain.Deny, pipeline.ReasonContained)

	// A control of a kind or scope this pipeline does not know fails closed.
	f.control(pipeline.ControlScopeAgent, f.agent.String(), "SOMETHING_NEW", "")
	expect(t, read(), adomain.Deny, pipeline.ReasonContained)
	f.control("somewhere_new", "x", pipeline.ControlDenyAll, "")
	expect(t, read(), adomain.Deny, pipeline.ReasonContained)

	f.w.Cont.Controls = nil
	expect(t, read(), adomain.Allow, pipeline.ReasonGrantCovers)
}

// TestHR248_GrantControlCoversDependants: a control on a grant covers runs
// under every grant issued from it (grant_lineage: the run's chain).
func TestHR248_GrantControlCoversDependants(t *testing.T) {
	f := newFx(t)
	child := f.grant
	child.ID, child.Revision, child.Parent, child.Depth = gdomain.NewGrantID(), 1, f.grant.ID, 1
	f.w.Grants.Put(child)
	run := f.newRun(child.ID)
	expect(t, f.call(run, "get_refund", `{"refund":"re_1"}`), adomain.Allow, pipeline.ReasonGrantCovers)
	f.control(pipeline.ControlScopeGrant, f.grant.ID.String(), pipeline.ControlDenyAll, "")
	expect(t, f.call(run, "get_refund", `{"refund":"re_1"}`), adomain.Deny, pipeline.ReasonContained)
}

// TestHR248_HoldWritesLetsReadsContinue: HOLD_WRITES never lets a write
// through, and reads continue.
func TestHR248_HoldWritesLetsReadsContinue(t *testing.T) {
	f := newFx(t)
	f.control(pipeline.ControlScopeAgent, f.agent.String(), pipeline.ControlHoldWrites, "")
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.Allow, pipeline.ReasonGrantCovers)
	ev := f.call(f.run, "create_refund", refund("ch_1", "10.00"))
	if ev.Permits() || ev.MonitorPermit() {
		t.Fatalf("a held write was permitted: %s %+v", ev.Decision, ev.Checklist)
	}
	if ev.Decisive().Code != pipeline.ReasonContainedWrites {
		t.Fatalf("decisive %s, want %s", ev.Decisive().Code, pipeline.ReasonContainedWrites)
	}
}
