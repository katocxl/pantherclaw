// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/runs/app"
)

// rangeAgent creates a range agent (G0 M12 D1).
func (w *world) rangeAgent(t *testing.T) ids.UUID {
	t.Helper()
	a, err := w.inv.Create(w.ownerCtx(), adomain.Details{
		Name: "range coder", TeamID: w.team, EnvironmentID: w.env, OwnerUserID: w.owner, Context: adomain.ContextCI, RangeAgent: true,
	})
	if err != nil || !a.RangeAgent {
		t.Fatalf("range agent: %+v, %v", a, err)
	}
	return a.ID
}

// TestHR220_StartRunTakesSimulatedFromTheAgent: every run of a range agent
// is simulated and a real agent's run never is; the flag is stored with the
// run and the caller names no part of it.
func TestHR220_StartRunTakesSimulatedFromTheAgent(t *testing.T) {
	w := newWorld(t)
	real, rng := w.agent(t), w.rangeAgent(t)
	for _, c := range []struct {
		agent ids.UUID
		want  bool
	}{{real, false}, {rng, true}} {
		r, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: c.agent})
		if err != nil || r.Simulated != c.want {
			t.Fatalf("run of %s: simulated=%v, %v, want %v", c.agent, r.Simulated, err, c.want)
		}
		got, err := w.svc.GetRun(w.ownerCtx(), r.ID)
		if err != nil || got.Simulated != c.want {
			t.Fatalf("read back: simulated=%v, %v, want %v", got.Simulated, err, c.want)
		}
		if n := w.count(t, "SELECT count(*) FROM pc.runs WHERE org_id = $1 AND id = $2 AND simulated = $3", w.org, r.ID, c.want); n != 1 {
			t.Fatalf("stored simulated != %v", c.want)
		}
	}
}

// TestHR220_SimulatedParentsStartOnlyRangeChildren (D2): a child run is
// simulated when its parent is or its agent is a range agent; a simulated
// parent may start children only of range agents, whatever the instance.
func TestHR220_SimulatedParentsStartOnlyRangeChildren(t *testing.T) {
	w := newWorld(t)
	real, realHelper, rng, rngHelper := w.agent(t), w.agent(t), w.rangeAgent(t), w.rangeAgent(t)
	ctx := context.Background()

	rInst := w.instance(t, rng, "ADMITTED")
	simRoot, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: rng, InstanceID: &rInst.Instance, TTL: time.Hour})
	if err != nil || !simRoot.Simulated {
		t.Fatalf("simulated root: %+v, %v", simRoot, err)
	}
	_, err = w.svc.StartChildRun(ctx, app.ChildInput{Caller: rInst, ParentRunID: simRoot.ID, AgentID: realHelper})
	wantCode(t, "simulated parent, real child agent", err, pcerr.FailedPrecondition, "SIMULATION_MISMATCH")
	child, err := w.svc.StartChildRun(ctx, app.ChildInput{Caller: rInst, ParentRunID: simRoot.ID, AgentID: rngHelper})
	if err != nil || !child.Simulated {
		t.Fatalf("simulated parent, range child agent: %+v, %v", child, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.runs WHERE org_id = $1 AND parent_run_id = $2", w.org, simRoot.ID); n != 1 {
		t.Fatalf("%d children of the simulated root, want only the range one", n)
	}

	// A real parent: a real child stays real; a child of a range agent is
	// simulated.
	inst := w.instance(t, real, "ADMITTED")
	realRoot, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: real, InstanceID: &inst.Instance, TTL: time.Hour})
	if err != nil || realRoot.Simulated {
		t.Fatalf("real root: %+v, %v", realRoot, err)
	}
	realChild, err := w.svc.StartChildRun(ctx, app.ChildInput{Caller: inst, ParentRunID: realRoot.ID, AgentID: realHelper})
	if err != nil || realChild.Simulated {
		t.Fatalf("real parent, real child: %+v, %v", realChild, err)
	}
	rangeChild, err := w.svc.StartChildRun(ctx, app.ChildInput{Caller: inst, ParentRunID: realRoot.ID, AgentID: rngHelper})
	if err != nil || !rangeChild.Simulated {
		t.Fatalf("real parent, range child: %+v, %v", rangeChild, err)
	}
	// A simulated run of a range agent never reaches a real agent either.
	rcInst := w.instance(t, rngHelper, "ADMITTED")
	deeper, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: rngHelper, InstanceID: &rcInst.Instance, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.svc.StartChildRun(ctx, app.ChildInput{Caller: rcInst, ParentRunID: deeper.ID, AgentID: real})
	wantCode(t, "grandchild of a real agent", err, pcerr.FailedPrecondition, "SIMULATION_MISMATCH")
}

// TestHR220_TransactionsTakeSimulatedFromTheirRun: the transaction insert
// copies the flag from the run, never from its caller; a consequence copies
// its parent's.
func TestHR220_TransactionsTakeSimulatedFromTheirRun(t *testing.T) {
	w := newWorld(t)
	real, rng := w.agent(t), w.rangeAgent(t)
	ctx := context.Background()
	for _, c := range []struct {
		agent ids.UUID
		want  bool
	}{{real, false}, {rng, true}} {
		r, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: c.agent})
		if err != nil {
			t.Fatal(err)
		}
		txn, conseq := ids.NewV7(), ids.NewV7()
		if err := w.pool.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			if err := q.InsertDecision(ctx, dbq.InsertDecisionParams{
				OrgID: w.org, ID: txn, RunID: r.ID, ActionID: ids.NewV7(), ActionHash: make([]byte, 32), Operation: "payments.refund.create",
				Decision: "ALLOW", ReasonCode: "R", GatewayID: "gw", State: "OPEN", Mode: "enforce",
			}); err != nil {
				return err
			}
			_, err := q.InsertConsequenceTransaction(ctx, dbq.InsertConsequenceTransactionParams{
				OrgID: w.org, ID: conseq, ActionID: ids.NewV7(), ActionHash: make([]byte, 32), Operation: "deploy.verify", Parent: txn,
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		for _, id := range []ids.UUID{txn, conseq} {
			if n := w.count(t, "SELECT count(*) FROM pc.transactions WHERE org_id = $1 AND id = $2 AND simulated = $3", w.org, id, c.want); n != 1 {
				t.Errorf("transaction %s of a run with simulated=%v: simulated differs", id, c.want)
			}
		}
	}
}
