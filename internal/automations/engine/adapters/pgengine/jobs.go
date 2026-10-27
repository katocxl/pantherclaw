// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// SweepInterval is how often due executions are woken (D24).
const SweepInterval = 15 * time.Second

// maxDue bounds one org's sweep; the next sweep takes the rest.
const maxDue = 500

// unique keeps one queued or running job per args. River requires the
// available, pending, running and scheduled states in ByState, so a sweep's
// wake is dropped while the execution's job runs (the next sweep wakes it
// again if it is still due). A wake for an event (a start, a launch claimed
// or completed) carries its own Wake id, so it is never dropped behind a
// running job that may have read the state before the event.
func unique() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// ExecutionKind is the kind of an execution's id in job arguments.
type ExecutionKind struct{}

// KindName implements ids.Kind.
func (ExecutionKind) KindName() string { return "automation execution" }

// WakeKind is the kind of one event wake's id in job arguments.
type WakeKind struct{}

// KindName implements ids.Kind.
func (WakeKind) KindName() string { return "automation wake" }

// ExecutionArgs asks for one execution to be advanced. Job args carry
// typed ids only (HR-056).
type ExecutionArgs struct {
	Org       ids.OrgID             `json:"org"`
	Execution ids.ID[ExecutionKind] `json:"execution"`
	// Wake is set on a wake for an event (enqueue) and empty on a sweep's.
	Wake ids.ID[WakeKind] `json:"wake,omitzero"`
}

// executionArgs is the job that advances execution id.
func executionArgs(org ids.OrgID, id ids.UUID) (ExecutionArgs, error) {
	x, err := ids.FromUUID[ExecutionKind](id)
	return ExecutionArgs{Org: org, Execution: x}, err
}

// Kind implements river.JobArgs.
func (ExecutionArgs) Kind() string { return "automation.execute" }

// InsertOpts keeps one queued job per execution.
func (ExecutionArgs) InsertOpts() river.InsertOpts { return unique() }

type executionWorker struct {
	river.WorkerDefaults[ExecutionArgs]
	e *Engine
}

func (w *executionWorker) Work(ctx context.Context, job *river.Job[ExecutionArgs]) error {
	return w.e.Advance(ctx, job.Args.Org, job.Args.Execution.UUID())
}

// SweepOrgArgs wakes one org's due executions.
type SweepOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SweepOrgArgs) Kind() string { return "automation.wake_org" }

// InsertOpts keeps one queued sweep per org.
func (SweepOrgArgs) InsertOpts() river.InsertOpts { return unique() }

type sweepOrgWorker struct {
	river.WorkerDefaults[SweepOrgArgs]
	e *Engine
}

// Work enqueues an ExecutionArgs for every due execution of the org.
func (w *sweepOrgWorker) Work(ctx context.Context, job *river.Job[SweepOrgArgs]) error {
	_, err := w.e.Sweep(ctx, job.Args.Org)
	return err
}

// Sweep enqueues the org's due executions and returns how many.
func (e *Engine) Sweep(ctx context.Context, org ids.OrgID) (int, error) {
	var due []ids.UUID
	err := e.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		due, err = dbq.New(tx).DueAutomationExecutions(ctx, org, maxDue)
		return err
	}, db.ReadOnly())
	if err != nil || len(due) == 0 {
		return 0, err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		if e.Client == nil {
			return 0, fmt.Errorf("automation sweep: %w", err)
		}
		client = e.Client
	}
	params := make([]river.InsertManyParams, 0, len(due))
	for _, id := range due {
		args, err := executionArgs(org, id)
		if err != nil {
			return 0, err
		}
		params = append(params, river.InsertManyParams{Args: args})
	}
	_, err = client.InsertMany(ctx, params)
	return len(due), err
}

// SweepArgs fans the wake sweep out to every active org.
type SweepArgs struct{}

// Kind implements river.JobArgs.
func (SweepArgs) Kind() string { return "automation.wake" }

type sweepWorker struct {
	river.WorkerDefaults[SweepArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one
// sweep per org.
func (w *sweepWorker) Work(ctx context.Context, _ *river.Job[SweepArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("automation wake: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SweepOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// Register adds the engine's workers to reg and returns its schedule.
func Register(reg *jobs.Registry, e *Engine) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[ExecutionArgs](reg, &executionWorker{e: e}); err != nil {
		return nil, err
	}
	if err := jobs.Register[SweepOrgArgs](reg, &sweepOrgWorker{e: e}); err != nil {
		return nil, err
	}
	if err := jobs.Register[SweepArgs](reg, &sweepWorker{pool: e.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepArgs{}, nil }, nil),
	}, nil
}
