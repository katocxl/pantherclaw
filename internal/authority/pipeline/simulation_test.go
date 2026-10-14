// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"reflect"
	"strings"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// simulatedRun adds a run of the fixture's agent with the given flag.
func (f *fx) simulatedRun(simulated bool) ids.UUID {
	id := ids.NewV7()
	f.w.AddRun(id, pipeline.Run{
		AgentID: f.agent, InstanceID: f.instance, Launcher: f.alice, Principal: f.alice, EnvironmentID: f.env,
		GrantID: f.grant.ID, Active: true, Simulated: simulated,
	})
	return id
}

// simulatedConn puts a connection of the fixture's gateway with the given flag.
func (f *fx) simulatedConn(simulated bool) ids.UUID {
	c := pipeline.Connection{
		ID: ids.NewV7(), Gateway: f.gateway, Kind: "http", Package: f.pkg.Name, State: "ACTIVE", AccessMode: "none",
		DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{}, Simulated: simulated,
	}
	f.w.PutConnection(c)
	return c.ID
}

func (f *fx) onConn(run, conn ids.UUID) *pipeline.Evaluation {
	f.t.Helper()
	f.conn = conn
	return f.call(run, "create_refund", refund("ch_1", "10.00"))
}

// TestHR220_SimulationMismatchIsDeniedBothWays (D4): a simulated run on a
// real connection and a realEv run on a simulated connection are both DENY
// SIMULATION_MISMATCH, as the decisive scope reason; matching pairs decide
// as before, and the decision records the run's flag.
func TestHR220_SimulationMismatchIsDeniedBothWays(t *testing.T) {
	f := newFx(t)
	for _, c := range []struct {
		run, conn bool
		want      adomain.Decision
		code      string
	}{
		{false, false, adomain.Allow, pipeline.ReasonGrantCovers},
		{true, true, adomain.Allow, pipeline.ReasonGrantCovers},
		{true, false, adomain.Deny, pipeline.ReasonSimulationMismatch},
		{false, true, adomain.Deny, pipeline.ReasonSimulationMismatch},
	} {
		ev := f.onConn(f.simulatedRun(c.run), f.simulatedConn(c.conn))
		expect(t, ev, c.want, c.code)
		if ev.Simulated != c.run {
			t.Errorf("run=%v conn=%v: the evaluation says simulated=%v", c.run, c.conn, ev.Simulated)
		}
		if c.want == adomain.Deny && ev.Decisive().Step != pipeline.StepScope {
			t.Errorf("run=%v conn=%v: decisive step %d, want scope", c.run, c.conn, ev.Decisive().Step)
		}
	}
}

// TestHR220_PolicyNeverSeesTheRangeMark (D4): neither the policy's input,
// nor the typed `run` and `action` shapes carry either flag.
func TestHR220_PolicyNeverSeesTheRangeMark(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[papp.Input](), reflect.TypeFor[papp.Run]()} {
		for i := range typ.NumField() {
			if n := strings.ToLower(typ.Field(i).Name); strings.Contains(n, "simulat") || strings.Contains(n, "range") {
				t.Errorf("%s.%s is visible to policy", typ.Name(), typ.Field(i).Name)
			}
		}
	}
	for name, fields := range map[string]map[string]struct{}{"run": schemaFields(papp.RunSchema), "action": schemaFields(papp.ActionSchema(&newFx(t).pkg.Definitions[0]))} {
		for field := range fields {
			if n := strings.ToLower(field); strings.Contains(n, "simulat") || strings.Contains(n, "range") {
				t.Errorf("`%s` exposes %s to policy", name, field)
			}
		}
	}
}

// TestT094_PolicyCannotTellRangeTrafficApart: the same action by a real
// run on a real connection and by a simulated run on a simulated connection
// gets the same decision, the same checklist and the same obligations.
func TestT094_PolicyCannotTellRangeTrafficApart(t *testing.T) {
	f := newFx(t)
	if err := f.w.SetPolicy([]pdomain.Rule{approvalOver50()}, nil); err != nil {
		t.Fatal(err)
	}
	for _, amount := range []string{"10.00", "75.00"} {
		realEv := f.eval(f.parse(f.simulatedRun(false), ids.NewV7(), "create_refund", refund("ch_1", amount)))
		f.conn = f.simulatedConn(true)
		sim := f.eval(f.parse(f.simulatedRun(true), ids.NewV7(), "create_refund", refund("ch_1", amount)))
		if realEv.Decision != sim.Decision || !reflect.DeepEqual(codes(realEv), codes(sim)) ||
			!reflect.DeepEqual(realEv.Obligations, sim.Obligations) || !reflect.DeepEqual(realEv.Approvals, sim.Approvals) {
			t.Errorf("%s: real %s %v, simulated %s %v", amount, realEv.Decision, codes(realEv), sim.Decision, codes(sim))
		}
		f.conn = f.simulatedConn(false)
	}
}

func schemaFields(s celenv.Schema) map[string]struct{} {
	out := map[string]struct{}{}
	for _, st := range s {
		for name := range st.Fields {
			out[name] = struct{}{}
		}
	}
	return out
}

func codes(ev *pipeline.Evaluation) []string {
	out := make([]string, len(ev.Checklist))
	for i, it := range ev.Checklist {
		out[i] = it.Check + ":" + it.Code
	}
	return out
}

// TestHR120_EarlyDenialsOfARangeRunAreStillSimulated: a range run whose
// identity does not match (so the decision is decided before containment)
// still records the run's flag, and a real run's does not.
func TestHR120_EarlyDenialsOfARangeRunAreStillSimulated(t *testing.T) {
	f := newFx(t)
	for _, sim := range []bool{true, false} {
		run := ids.NewV7()
		f.w.AddRun(run, pipeline.Run{
			AgentID: ids.NewV7(), InstanceID: f.instance, Launcher: f.alice, Principal: f.alice, EnvironmentID: f.env,
			GrantID: f.grant.ID, Active: true, Simulated: sim,
		})
		f.conn = f.simulatedConn(sim)
		ev := f.call(run, "create_refund", refund("ch_1", "10.00"))
		expect(t, ev, adomain.Deny, pipeline.ReasonRunMismatch)
		if ev.Simulated != sim {
			t.Errorf("simulated=%v run: the denial says %v", sim, ev.Simulated)
		}
	}
}

// TestHR220_ASimulatedRunNeverGetsAnAllowWithoutAConnection: an action on a
// channel that names no connection is DENY SIMULATION_MISMATCH for a range
// run, and still decided as before for a real run.
func TestHR220_ASimulatedRunNeverGetsAnAllowWithoutAConnection(t *testing.T) {
	f := newFx(t)
	for _, sim := range []bool{false, true} {
		req := f.parse(f.simulatedRun(sim), ids.NewV7(), "create_refund", refund("ch_1", "10.00"))
		req.Action.Action.Connection, req.Action.Action.Channel = "", "cli"
		ev := f.eval(req)
		if sim {
			expect(t, ev, adomain.Deny, pipeline.ReasonSimulationMismatch)
		} else if ev.Decision == adomain.Deny && ev.Decisive().Code == pipeline.ReasonSimulationMismatch {
			t.Error("a real run without a connection was denied as a mismatch")
		}
	}
}
