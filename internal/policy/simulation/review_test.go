// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// errClosedPool is what a closed pool returns: a plain error, named by no
// type the runner knows, so it must fail the step rather than count.
var errClosedPool = errors.New("closed pool")

// ticking is a clock that moves a minute each time it is read.
type ticking struct{ t time.Time }

func (c *ticking) Now() time.Time {
	c.t = c.t.Add(time.Minute)
	return c.t
}

// TestHR237_SimulationCountsAChunkOnceAcrossTwoSteps: two steps that read
// one stored cursor (a rescued job beside its successor) count the chunk
// once: the second to record finds the simulation moved on and drops its
// chunk, and the run still counts every decision exactly once (D34).
func TestHR237_SimulationCountsAChunkOnceAcrossTwoSteps(t *testing.T) {
	w := newWorld(billing.Team)
	w.record(10, "payments.refund.create", outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.Deny, propReason: "NO"})
	s := w.simulate(t, simulation.Request{})
	// One chunk per step: the clock moves a minute each time it is read.
	w.runner.Chunk, w.runner.Budget, w.runner.Clock = 5, time.Second, &ticking{now}
	inner := false
	w.replay.onReplay = func() {
		if inner {
			return
		}
		inner = true
		// While the first step replays its chunk, a second step reads
		// the same cursor and records the same chunk first.
		more, err := w.runner.Step(context.Background(), org, s.ID)
		if err != nil || !more {
			t.Errorf("the second step: %v %v", more, err)
		}
	}
	more, err := w.runner.Step(context.Background(), org, s.ID)
	if err != nil || more {
		t.Fatalf("the first step: %v %v (it must stop: another step counted its chunk)", more, err)
	}
	if got := w.store.sims[s.ID]; got.Evaluated != 5 || got.Report.Counts.Total() != 5 || len(w.store.samples[s.ID]) != 5 {
		t.Fatalf("after two steps on one cursor: %d evaluated, %d counted, %d samples", got.Evaluated, got.Report.Counts.Total(),
			len(w.store.samples[s.ID]))
	}
	w.replay.onReplay = nil
	done := w.run(t, s.ID)
	if done.State != simulation.Done || done.Evaluated != 10 || done.Report.Counts[replay.NewlyDenied] != 10 {
		t.Fatalf("finished: %s %d %v", done.State, done.Evaluated, done.Report.Counts)
	}
}

// TestHR237_SimulationFailsWhenTheEditionLapses: a queued run whose
// licence lapsed fails with EDITION_REQUIRED and replays nothing; its
// results stay readable and it can no longer be canceled (D34).
func TestHR237_SimulationFailsWhenTheEditionLapses(t *testing.T) {
	w := newWorld(billing.Team)
	w.record(3, "payments.refund.create", outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.Allow, propReason: "GRANT_COVERS"})
	s := w.simulate(t, simulation.Request{})
	w.runner.Editions = editions(billing.Community)
	if more, err := w.runner.Step(context.Background(), org, s.ID); err != nil || more {
		t.Fatalf("step after the lapse: %v %v", more, err)
	}
	got, err := w.svc.Get(as(td.RolePolicyAuthor), s.ID)
	if err != nil || got.State != simulation.Failed || got.Error != simulation.FailEdition || w.replay.calls != 0 {
		t.Fatalf("lapsed run: %+v %v, %d replays", got, err, w.replay.calls)
	}
	if _, err := w.svc.Samples(as(td.RolePolicyAuthor), s.ID, simulation.SampleFilter{}, 0, ""); err != nil {
		t.Fatalf("samples of a lapsed run: %v", err)
	}
	w.runner.Editions = nil
	second := w.simulate(t, simulation.Request{})
	if _, err := w.runner.Step(context.Background(), org, second.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := w.svc.Get(as(td.RolePolicyAuthor), second.ID); got.State != simulation.Failed {
		t.Fatalf("a worker without entitlements ran a simulation: %s", got.State)
	}
}

// TestHR237_AnUnreadableDecisionIsUnevaluable: a stored receipt that does
// not parse (not a compact JWS, its payload not base64) counts that one
// decision unevaluable (INPUTS_UNREADABLE) and the run goes on (D34);
// any other error, such as a closed pool's plain one, fails the step for a
// retry without counting anything, and the retry resumes where the last
// chunk ended (D38).
func TestHR237_AnUnreadableDecisionIsUnevaluable(t *testing.T) {
	w := newWorld(billing.Team)
	w.record(4, "payments.refund.create", outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.Allow, propReason: "GRANT_COVERS"})
	w.replay.errs = map[ids.UUID]error{
		w.store.recorded[1].Transaction: errors.New("replay: the decision receipt is not a compact JWS"),
		w.store.recorded[2].Transaction: fmt.Errorf("replay: the decision receipt: %w", base64.CorruptInputError(7)),
	}
	s := w.run(t, w.simulate(t, simulation.Request{}).ID)
	samples, err := w.svc.Samples(as(td.RolePolicyAuthor), s.ID, simulation.SampleFilter{Category: replay.Unevaluable}, 0, "")
	if err != nil || s.Report.Counts[replay.Unevaluable] != 2 || s.Report.Counts[replay.Unchanged] != 2 || len(samples.Items) != 2 ||
		samples.Items[0].Limitations[0] != replay.IncompleteInputsUnreadable || samples.Items[1].Limitations[0] != replay.IncompleteInputsUnreadable {
		t.Fatalf("unreadable decision: %v %+v %v", s.Report.Counts, samples.Items, err)
	}

	w = newWorld(billing.Team)
	w.record(4, "payments.refund.create", outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.Allow, propReason: "GRANT_COVERS"})
	w.runner.Chunk = 2
	w.replay.errs = map[ids.UUID]error{w.store.recorded[2].Transaction: fmt.Errorf("replay: the decision receipt: %w", errClosedPool)}
	id := w.simulate(t, simulation.Request{}).ID
	if _, err := w.runner.Step(context.Background(), org, id); !errors.Is(err, errClosedPool) {
		t.Fatalf("a closed pool: %v", err)
	}
	if got := w.store.sims[id]; got.State != simulation.Running || got.Evaluated != 2 {
		t.Fatalf("after the failed step: %s %d", got.State, got.Evaluated)
	}
	w.replay.errs = nil
	if got := w.run(t, id); got.State != simulation.Done || got.Evaluated != 4 || got.Report.Counts[replay.Unchanged] != 4 {
		t.Fatalf("the retry: %s %d %v", got.State, got.Evaluated, got.Report.Counts)
	}
}

type countingSource struct {
	replay.Source
	reads int
}

func (c *countingSource) PolicyVersion(_ context.Context, _ ids.OrgID, id ids.UUID) (*pdomain.Bundle, error) {
	c.reads++
	if id != version {
		return nil, replay.ErrNotFound
	}
	return proposedBundle, nil
}

// TestVersionCacheReadsAVersionOnce: the worker's replay source reads a
// proposed version once per version, and passes a missing one through.
func TestVersionCacheReadsAVersionOnce(t *testing.T) {
	src := &countingSource{}
	c := &simulation.VersionCache{Source: src}
	for range 50 {
		if b, err := c.PolicyVersion(context.Background(), org, version); err != nil || b != proposedBundle {
			t.Fatalf("cached read: %v %v", b, err)
		}
	}
	if _, err := c.PolicyVersion(context.Background(), org, ids.NewV7()); !errors.Is(err, replay.ErrNotFound) {
		t.Fatalf("a missing version: %v", err)
	}
	if src.reads != 2 {
		t.Fatalf("%d reads of the source", src.reads)
	}
}
