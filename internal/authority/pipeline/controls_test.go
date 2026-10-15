// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func (f *fx) control(scopeType, scopeID, control, op string) {
	f.w.ActiveControls = []pipeline.Control{{ID: ids.NewV7(), ScopeType: scopeType, ScopeID: scopeID, Control: control, Operation: op}}
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

	f.w.ActiveControls = nil
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

// TestHR248_HoldWritesLetsReadsContinue: under HOLD_WRITES reads continue
// and a write is held for one independent responder (KindContainment),
// never permitted; on a monitor-mode route, which cannot hold, the write
// is denied.
func TestHR248_HoldWritesLetsReadsContinue(t *testing.T) {
	f := newFx(t)
	f.control(pipeline.ControlScopeAgent, f.agent.String(), pipeline.ControlHoldWrites, "")
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.Allow, pipeline.ReasonGrantCovers)
	ev := f.call(f.run, "create_refund", refund("ch_1", "10.00"))
	expect(t, ev, adomain.RequireApproval, pipeline.ReasonContainedWrites)
	if ev.Permits() || ev.MonitorPermit() || ev.Hold == nil {
		t.Fatalf("a held write: permits %v, hold %+v", ev.Permits(), ev.Hold)
	}
	want := apdomain.Requirement{
		Kind: apdomain.KindContainment, Count: 1, Independent: true,
		Sources: []apdomain.Source{{Level: "containment", Reason: pipeline.ReasonContainedWrites}},
	}
	if len(ev.Hold.Requirements) != 1 || !reflect.DeepEqual(ev.Hold.Requirements[0], want) {
		t.Fatalf("hold requirements %+v", ev.Hold.Requirements)
	}

	c, err := f.w.Connection(context.Background(), org, f.conn)
	if err != nil {
		t.Fatal(err)
	}
	c.DefaultMode = pipeline.ModeMonitor
	f.w.PutConnection(c)
	ev = f.call(f.run, "create_refund", refund("ch_1", "10.00"))
	expect(t, ev, adomain.Deny, pipeline.ReasonContainedWrites)
	if ev.MonitorPermit() {
		t.Fatal("a monitor-mode write was permitted under HOLD_WRITES")
	}
}

// TestHR248_ControlsFailClosed (D53): more controls matching an action than
// the pipeline checks deny it CONTAINMENT_UNAVAILABLE, and controls that
// cannot be read leave it undecidable; neither is ever allowed.
func TestHR248_ControlsFailClosed(t *testing.T) {
	f := newFx(t)
	many := make([]pipeline.Control, pipeline.MaxControls+1)
	for i := range many {
		many[i] = pipeline.Control{ID: ids.NewV7(), ScopeType: pipeline.ControlScopeRun, ScopeID: ids.NewV7().String(), Control: pipeline.ControlDenyAll}
	}
	f.w.ActiveControls = many
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.Deny, pipeline.ReasonContainmentUnavailable)
	f.w.ActiveControls = nil
	f.w.Fail["Controls"] = true
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.CannotAuthorize, pipeline.ReasonEvidenceUnavailable)
	delete(f.w.Fail, "Controls")
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.Allow, pipeline.ReasonGrantCovers)
}

// TestHR248_ControlIdsAndResourcesMatchWhateverTheirCase (D53): an upper-case
// uuid still covers its subject, and a resource control covers its target
// whatever the case of either (covering more is the safe direction).
func TestHR248_ControlIdsAndResourcesMatchWhateverTheirCase(t *testing.T) {
	f := newFx(t)
	read := func() *pipeline.Evaluation { return f.call(f.run, "get_refund", `{"refund":"re_1"}`) }
	f.control(pipeline.ControlScopeAgent, strings.ToUpper(f.agent.String()), pipeline.ControlDenyAll, "")
	expect(t, read(), adomain.Deny, pipeline.ReasonContained)
	f.control(pipeline.ControlScopeResource, "PAYMENTS.REFUND:RE_*", pipeline.ControlDenyAll, "")
	expect(t, read(), adomain.Deny, pipeline.ReasonContained)
	f.control(pipeline.ControlScopePrincipal, strings.ToUpper(f.alice.String()), pipeline.ControlDenyAll, "")
	expect(t, read(), adomain.Deny, pipeline.ReasonContained)
}
