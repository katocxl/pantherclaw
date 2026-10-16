// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Stubs are a scenario's would-be step results by step id (D34): each Run
// or Poll of that step takes the next one; once they run out the last one
// repeats (so a WAITING stub waits until the step's timeout). A step
// without stubs returns DONE with no effect and no evidence.
type Stubs map[string][]autodomain.StepResult

// MaxSimulationSteps bounds a simulation (transitions plus clock jumps):
// a 7-day deadline polled every 15 s fits.
const MaxSimulationSteps = 100_000

// ErrSimulation reports a simulation that could not finish.
var ErrSimulation = errors.New("engine: simulation")

// Simulation is the outcome of Simulate.
type Simulation struct {
	State    autodomain.ExecutionState
	Reason   string
	Result   Result
	Attempts []Attempt
	// Elapsed is the simulated time from start to the final state.
	Elapsed time.Duration
}

// Simulate runs def's steps for trigger in TEST mode with the same Machine
// as live executions, entirely in memory: no transaction, no hooks, no
// effects (HR-288). The clock is advanced to each wait's wake time. The
// trigger's Mode is forced to TEST.
func Simulate(ctx context.Context, def *autodomain.Definition, trigger autodomain.TriggerRef, stubs Stubs,
	clk *clock.Fake,
) (Simulation, error) {
	if def == nil || clk == nil {
		return Simulation{}, fmt.Errorf("%w: a definition and a clock are needed", ErrSimulation)
	}
	reg := autoports.StepRegistry{}
	for _, k := range autodomain.Kinds() {
		reg[k] = &stubStep{kind: k, stubs: stubs}
	}
	m, err := NewMachine(reg, NopHooks{}, clk.Now)
	if err != nil {
		return Simulation{}, err
	}
	m.Stubbed = true
	trigger.Mode = autodomain.ModeTest
	start := clk.Now()
	x := &Exec{
		ID: ids.NewV7(), Org: trigger.Org, Automation: trigger.Automation, Version: trigger.Version, Mode: autodomain.ModeTest,
		Def: def, State: autodomain.ExecPending, DeadlineAt: start.Add(def.Limits.DeadlineOrDefault()),
		View: autodomain.ExecutionView{
			Automation: trigger.Automation, AutomationName: def.Name, Version: trigger.Version, Trigger: trigger,
			Mode: autodomain.ModeTest, Owner: def.Owner.UUID(), StartedAt: start,
		},
	}
	x.View.ID = x.ID
	x.View.DeadlineAt = x.DeadlineAt
	for range MaxSimulationSteps {
		if !x.Active() {
			break
		}
		if x.State == autodomain.ExecWaiting && x.WakeAt.After(clk.Now()) {
			clk.Set(x.WakeAt)
		}
		if _, err := m.Advance(ctx, nil, x); err != nil {
			return Simulation{}, err
		}
	}
	if x.Active() {
		return Simulation{}, fmt.Errorf("%w: no final state after %d steps", ErrSimulation, MaxSimulationSteps)
	}
	out := Simulation{State: x.State, Reason: x.Reason, Elapsed: clk.Now().Sub(start)}
	if x.Result != nil {
		out.Result = *x.Result
	}
	for _, a := range x.Attempts {
		out.Attempts = append(out.Attempts, *a)
	}
	return out, nil
}

// stubStep returns a scenario's results for one kind.
type stubStep struct {
	kind  string
	stubs Stubs
	used  map[string]int
}

func (s *stubStep) Kind() string { return s.kind }

func (s *stubStep) next(sc autodomain.StepContext) autodomain.StepResult {
	rs := s.stubs[sc.Spec.ID]
	if len(rs) == 0 {
		return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone}
	}
	if s.used == nil {
		s.used = map[string]int{}
	}
	key := sc.Spec.ID
	i := min(s.used[key], len(rs)-1)
	s.used[key]++
	return rs[i]
}

func (s *stubStep) Run(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.next(sc), nil
}

func (s *stubStep) Poll(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.next(sc), nil
}

func (s *stubStep) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.next(sc), nil
}
