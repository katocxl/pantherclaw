// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// RollupInterval is how often the dispatcher runs. A rollup runs once per
// UTC day, so running more often only fills the day sooner.
const RollupInterval = time.Hour

// RollupOrgArgs asks for one org's daily rollup. Job args carry ids only
// (HR-056).
type RollupOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (RollupOrgArgs) Kind() string { return "postureview.rollup_org" }

// InsertOpts keeps one queued job per org.
func (RollupOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type rollupWorker struct {
	river.WorkerDefaults[RollupOrgArgs]
	r   *Rollup
	log *slog.Logger
}

func (w *rollupWorker) Work(ctx context.Context, job *river.Job[RollupOrgArgs]) error {
	wrote, err := w.r.Run(ctx, job.Args.Org)
	if err == nil && wrote {
		w.log.InfoContext(ctx, "postureview.rolled_up", slog.String("org", job.Args.Org.String()))
	}
	return err
}

// RollupDispatchArgs fans the rollup out to every active org.
type RollupDispatchArgs struct{}

// Kind implements river.JobArgs.
func (RollupDispatchArgs) Kind() string { return "postureview.rollup_dispatch" }

type rollupDispatcher struct {
	river.WorkerDefaults[RollupDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *rollupDispatcher) Work(ctx context.Context, _ *river.Job[RollupDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("posture rollup: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: RollupOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterRollup adds the rollup workers to reg and returns the schedule.
func RegisterRollup(reg *jobs.Registry, r *Rollup, log *slog.Logger) ([]*river.PeriodicJob, error) {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[RollupOrgArgs](reg, &rollupWorker{r: r, log: log}); err != nil {
		return nil, err
	}
	if err := jobs.Register[RollupDispatchArgs](reg, &rollupDispatcher{pool: r.Service.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(RollupInterval),
			func() (river.JobArgs, *river.InsertOpts) { return RollupDispatchArgs{}, nil }, nil),
	}, nil
}
