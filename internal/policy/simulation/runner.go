// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Replayer is the replay engine (replay.Engine): read ports only.
type Replayer interface {
	Replay(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, proposed *ids.UUID) (*replay.Outcome, error)
}

// Limitation codes of an unevaluable decision besides the replay's own.
const (
	// NotReproduced: replayed with its recorded policy, the decision is not
	// the recorded one, so a difference under the version would mean
	// nothing.
	NotReproduced = "NOT_REPRODUCED"
	// Failure reasons of a FAILED simulation.
	FailVersionGone = "POLICY_VERSION_NOT_FOUND"
	FailReplay      = "REPLAY_FAILED"
)

// Defaults of a runner.
const (
	DefaultChunk  = 100
	DefaultBudget = 40 * time.Second
)

// Runner runs simulations a chunk at a time: each chunk's recorded
// decisions are replayed outside any transaction, then counted, sampled
// and the cursor moved in one transaction, so a retried chunk is counted
// once.
type Runner struct {
	Store    Store
	Replay   Replayer
	Versions Versions
	// Chunk is how many decisions a chunk replays; Budget how long one
	// Step runs before it hands over to a new job.
	Chunk  int
	Budget time.Duration
	Clock  clock.Clock
}

func (r *Runner) now() time.Time {
	if r.Clock == nil {
		return time.Now()
	}
	return r.Clock.Now()
}

// Step runs simulation id of org until it finishes, is cancelled or its
// budget is spent; more reports that it has not finished. An error is a
// failure to retry: the next Step resumes from the stored cursor.
func (r *Runner) Step(ctx context.Context, org ids.OrgID, id ids.UUID) (more bool, err error) {
	chunk, budget := r.Chunk, r.Budget
	if chunk <= 0 {
		chunk = DefaultChunk
	}
	if budget <= 0 {
		budget = DefaultBudget
	}
	deadline := r.now().Add(budget)
	sim, running, err := r.start(ctx, org, id)
	if err != nil || !running {
		return false, err
	}
	bundle, err := r.Versions.PolicyVersion(ctx, org, sim.Version)
	if errors.Is(err, replay.ErrNotFound) {
		return false, r.Fail(ctx, org, id, FailVersionGone)
	} else if err != nil {
		return false, err
	}
	for {
		var recs []Recorded
		if err := r.Store.InTx(ctx, org, true, func(ctx context.Context, tx Tx) error {
			recs, err = tx.Receipts(ctx, sim, min(chunk, sim.Max-sim.Evaluated))
			return err
		}); err != nil {
			return false, err
		}
		results := make([]Result, 0, len(recs))
		for _, rec := range recs {
			res, err := r.evaluate(ctx, org, sim.Version, bundle, rec)
			if err != nil {
				return false, err
			}
			results = append(results, res)
		}
		var cont bool
		if sim, cont, err = r.record(ctx, org, id, results, len(recs) < chunk); err != nil || !cont {
			return false, err
		}
		if r.now().After(deadline) {
			return true, nil
		}
	}
}

// start loads the simulation and starts it when queued; running is false
// when it is finished or cancelled.
func (r *Runner) start(ctx context.Context, org ids.OrgID, id ids.UUID) (Simulation, bool, error) {
	var sim Simulation
	running := false
	err := r.Store.InTx(ctx, org, false, func(ctx context.Context, tx Tx) error {
		cur, err := tx.Get(ctx, id, true)
		if err != nil {
			return err
		}
		switch cur.State {
		case Queued:
			sim, running, err = tx.Start(ctx, id)
			return err
		case Running:
			sim, running = cur, true
		case Done, Failed, Cancelled:
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return Simulation{}, false, nil // nothing to run
	}
	return sim, running, err
}

// record counts a chunk, keeps its samples within the bounds and moves the
// cursor, in one transaction; last finishes the simulation. cont is false
// when the simulation finished or was cancelled meanwhile.
func (r *Runner) record(ctx context.Context, org ids.OrgID, id ids.UUID, results []Result, last bool) (Simulation, bool, error) {
	var out Simulation
	cont := false
	err := r.Store.InTx(ctx, org, false, func(ctx context.Context, tx Tx) error {
		cur, err := tx.Get(ctx, id, true)
		if err != nil {
			return err
		}
		if cur.State != Running {
			return nil // cancelled meanwhile: nothing more is counted
		}
		have, err := tx.SampleCounts(ctx, id)
		if err != nil {
			return err
		}
		for _, res := range results {
			cur.Report.Add(res)
			byOp := have[res.Category]
			if byOp == nil {
				byOp = map[string]int{}
				have[res.Category] = byOp
			}
			if byOp[res.Operation] < SamplesPerGroup {
				if err := tx.InsertSample(ctx, id, SampleOf(res)); err != nil {
					return err
				}
				byOp[res.Operation]++
			}
		}
		cur.Evaluated += len(results)
		if n := len(results); n > 0 {
			l := results[n-1]
			cur.Cursor = &Cursor{Created: l.Recorded, Transaction: l.Transaction, Evaluation: l.Evaluation}
		}
		if last || cur.Evaluated >= cur.Max {
			cur.State = Done
		}
		var ok bool
		if out, ok, err = tx.Advance(ctx, cur); err != nil || !ok {
			return err
		}
		cont = out.State == Running
		return nil
	})
	return out, cont, err
}

// Fail marks a running or queued simulation FAILED with a reason code.
func (r *Runner) Fail(ctx context.Context, org ids.OrgID, id ids.UUID, reason string) error {
	return r.Store.InTx(ctx, org, false, func(ctx context.Context, tx Tx) error {
		cur, err := tx.Get(ctx, id, true)
		if err != nil {
			return err
		}
		if cur.State == Queued {
			if cur, _, err = tx.Start(ctx, id); err != nil {
				return err
			}
		}
		if cur.State != Running {
			return nil
		}
		cur.State, cur.Error = Failed, reason
		_, _, err = tx.Advance(ctx, cur)
		return err
	})
}

// evaluate replays one recorded decision with its recorded policy and with
// the version (D13's method) and classifies it (D5). A decision that does
// not reproduce, or that the version cannot evaluate on the recorded
// inputs, is unevaluable with the limitation codes.
func (r *Runner) evaluate(ctx context.Context, org ids.OrgID, version ids.UUID, b *pdomain.Bundle, rec Recorded) (Result, error) {
	res := Result{Transaction: rec.Transaction, Evaluation: rec.Evaluation, Agent: rec.Agent, Operation: rec.Operation, Recorded: rec.Created}
	base, err := r.Replay.Replay(ctx, org, rec.Transaction, rec.Evaluation, nil)
	if err != nil {
		return Result{}, fmt.Errorf("simulation: replay %s/%d: %w", rec.Transaction, rec.Evaluation, err)
	}
	res.Original, res.OrigReason = base.Original.Decision, base.Original.Reason
	switch {
	case !base.Complete:
		return unevaluable(res, base.Incomplete), nil
	case !base.Reproduced:
		res.Category, res.Limitations = Unevaluable, []string{NotReproduced}
		return res, nil
	}
	prop, err := r.Replay.Replay(ctx, org, rec.Transaction, rec.Evaluation, &version)
	if err != nil {
		return Result{}, fmt.Errorf("simulation: replay %s/%d under the version: %w", rec.Transaction, rec.Evaluation, err)
	}
	if !prop.Complete {
		return unevaluable(res, prop.Incomplete), nil
	}
	res.Proposed, res.PropReason = prop.Decision, prop.Reason
	res.Category = Classify(res.Original, res.Proposed, res.OrigReason, res.PropReason)
	if res.Category == NewlyHeld {
		res.Role = heldRole(b, prop.Decision, prop.Checklist)
	}
	return res, nil
}

func unevaluable(res Result, lims []replay.Limitation) Result {
	res.Category = Unevaluable
	for _, l := range lims {
		code := strings.ToUpper(l.Code)
		if !slices.Contains(res.Limitations, code) {
			res.Limitations = append(res.Limitations, code)
		}
	}
	if len(res.Limitations) == 0 {
		res.Limitations = []string{replay.IncompleteInputUnavailable}
	}
	return res
}
