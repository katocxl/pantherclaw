// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exports

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// SweepTimeout fits one org's sweep of destinations that answer slowly:
// every notice just inside a request's limit and every abort at all its
// attempts. One that does not answer ends the sweep's step at its first
// timeout.
const SweepTimeout = maxSweepItems*RequestTimeout + maxSweepItems*(abortAttempts+1)*abortTimeout + time.Minute

// SweepOrgArgs asks for one org's sweep. Job args carry ids only (HR-056).
type SweepOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SweepOrgArgs) Kind() string { return "exports.sweep_org" }

// InsertOpts keeps one queued job per org, on the notifications queue: one
// org's slow destination never holds up another's sweep. The next hour is
// the retry.
func (SweepOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: napp.Queue, MaxAttempts: 1, UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type sweepOrgWorker struct {
	river.WorkerDefaults[SweepOrgArgs]
	svc *Service
}

// Timeout leaves room for the sweep's requests.
func (w *sweepOrgWorker) Timeout(*river.Job[SweepOrgArgs]) time.Duration { return SweepTimeout }

func (w *sweepOrgWorker) Work(ctx context.Context, job *river.Job[SweepOrgArgs]) error {
	return w.svc.Sweep(ctx, job.Args.Org)
}

// SweepDispatchArgs fans the sweep out to every active org.
type SweepDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SweepDispatchArgs) Kind() string { return "exports.sweep_dispatch" }

type sweepDispatchWorker struct {
	river.WorkerDefaults[SweepDispatchArgs]
	pool *db.Pool
}

// sweepJobs lists orgs through the audited lister (HR-054): one job each.
func sweepJobs(ctx context.Context, pool *db.Pool) ([]river.InsertManyParams, error) {
	refs, err := pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil {
		return nil, err
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SweepOrgArgs{Org: r.Org}})
	}
	return params, nil
}

// Work enqueues one job per org; an org with nothing to do exits at once.
func (w *sweepDispatchWorker) Work(ctx context.Context, _ *river.Job[SweepDispatchArgs]) error {
	params, err := sweepJobs(ctx, w.pool)
	if err != nil || len(params) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("exports sweep dispatch: %w", err)
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// Register adds the workers to reg and returns the sweep's schedule.
func Register(reg *jobs.Registry, svc *Service) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[PushArgs](reg, &pushWorker{svc: svc}); err != nil {
		return nil, err
	}
	if err := jobs.Register[SweepOrgArgs](reg, &sweepOrgWorker{svc: svc}); err != nil {
		return nil, err
	}
	if err := jobs.Register[SweepDispatchArgs](reg, &sweepDispatchWorker{pool: svc.pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepDispatchArgs{}, nil }, nil),
	}, nil
}
