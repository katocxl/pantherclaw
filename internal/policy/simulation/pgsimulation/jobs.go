// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgsimulation

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
)

// JobTimeout bounds one step of a simulation: the runner's budget plus
// one chunk, well under River's stuck-job rescue.
const JobTimeout = 3 * time.Minute

// SimulateArgs runs one step of a simulation. Job args carry ids only
// (HR-056). A step that does not finish enqueues the next one.
type SimulateArgs struct {
	Org        ids.OrgID `json:"org"`
	Simulation ids.UUID  `json:"simulation"`
	Step       int       `json:"step,omitzero"`
}

// Kind implements river.JobArgs.
func (SimulateArgs) Kind() string { return "policy_simulate" }

type simulateWorker struct {
	river.WorkerDefaults[SimulateArgs]
	r   *simulation.Runner
	log *slog.Logger
}

func (w *simulateWorker) Timeout(*river.Job[SimulateArgs]) time.Duration { return JobTimeout }

// Work runs a step. A step that keeps failing marks the simulation FAILED
// on its last attempt, so the org is not left with a simulation that never
// finishes.
func (w *simulateWorker) Work(ctx context.Context, job *river.Job[SimulateArgs]) error {
	a := job.Args
	more, err := w.r.Step(ctx, a.Org, a.Simulation)
	if err != nil {
		if job.Attempt < job.MaxAttempts {
			return err
		}
		w.log.WarnContext(ctx, "policy.simulation_failed", slog.String("org", a.Org.String()),
			slog.String("simulation", a.Simulation.String()), pclog.Err(err))
		return w.r.Fail(context.WithoutCancel(ctx), a.Org, a.Simulation, simulation.FailReplay)
	}
	if !more {
		return nil
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("policy simulation: %w", err)
	}
	_, err = client.Insert(ctx, SimulateArgs{Org: a.Org, Simulation: a.Simulation, Step: a.Step + 1}, nil)
	return err
}

// Register adds the simulation worker to reg.
func Register(reg *jobs.Registry, r *simulation.Runner, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	return jobs.Register[SimulateArgs](reg, &simulateWorker{r: r, log: log})
}
