// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// DispatchInterval is how often the engine looks at every org (D10).
const DispatchInterval = 5 * time.Second

// maxBatchesPerJob bounds one org's job; the next dispatch takes the rest.
const maxBatchesPerJob = 20

// OrgArgs asks for one org's feed to be evaluated. Job args carry ids only
// (HR-056).
type OrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (OrgArgs) Kind() string { return "detection.evaluate_org" }

// InsertOpts keeps one queued job per org.
func (OrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type orgWorker struct {
	river.WorkerDefaults[OrgArgs]
	e *Engine
}

// Work evaluates full batches until the org is caught up, or the job's
// bound; it exits at once when there is nothing new.
func (w *orgWorker) Work(ctx context.Context, job *river.Job[OrgArgs]) error {
	for range maxBatchesPerJob {
		r, err := w.e.Process(ctx, job.Args.Org)
		if errors.Is(err, ErrCursorMoved) {
			return nil
		}
		if err != nil {
			return err
		}
		if r.Signals > 0 {
			w.e.log().InfoContext(ctx, "detection.signals", slog.String("org", job.Args.Org.String()),
				slog.Int("events", r.Events), slog.Int("signals", r.Signals))
		}
		if r.To-r.From < int64(feed.MaxBatch) {
			return nil
		}
	}
	return nil
}

// DispatchArgs fans evaluation out to every active org.
type DispatchArgs struct{}

// Kind implements river.JobArgs.
func (DispatchArgs) Kind() string { return "detection.dispatch" }

type dispatchWorker struct {
	river.WorkerDefaults[DispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org (D3).
func (w *dispatchWorker) Work(ctx context.Context, _ *river.Job[DispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("detection dispatch: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: OrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// Register adds the engine's workers to reg and returns its schedule.
func Register(reg *jobs.Registry, e *Engine) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[OrgArgs](reg, &orgWorker{e: e}); err != nil {
		return nil, err
	}
	if err := jobs.Register[DispatchArgs](reg, &dispatchWorker{pool: e.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(DispatchInterval),
			func() (river.JobArgs, *river.InsertOpts) { return DispatchArgs{}, nil }, nil),
	}, nil
}
