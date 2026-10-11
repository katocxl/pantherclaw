// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package retention

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// ListDue is the lister purpose retention_due: active orgs without a
// successful run in the last day (migration 00072).
const ListDue db.ListerPurpose = "retention_due"

// Jobs. An hourly dispatcher lists due orgs through the audited cross-org
// lister and enqueues one unique job per org (HR-054, HR-056: ids only),
// so every org runs about once a day.
const (
	// DispatchInterval is how often due orgs are looked for.
	DispatchInterval = time.Hour

	maxOrgsPerDispatch = 1000
	// runTimeout stays below River's stuck-job rescue (10 minutes).
	runTimeout = 9 * time.Minute
)

// OrgArgs asks for one org's retention run.
type OrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (OrgArgs) Kind() string { return "evidence.retention_org" }

// InsertOpts makes the job unique per org while queued or running.
func (OrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// DispatchArgs asks for a run of every due org.
type DispatchArgs struct{}

// Kind implements river.JobArgs.
func (DispatchArgs) Kind() string { return "evidence.retention_dispatch" }

type orgWorker struct {
	river.WorkerDefaults[OrgArgs]
	r *Remover
}

func (w *orgWorker) Timeout(*river.Job[OrgArgs]) time.Duration { return runTimeout }

// Work runs the org. A failed run was recorded and logged; the next
// dispatch tries again, so it ends without a retry.
func (w *orgWorker) Work(ctx context.Context, job *river.Job[OrgArgs]) error {
	_, err := w.r.Run(ctx, job.Args.Org)
	if err != nil && ctx.Err() != nil {
		return err
	}
	return nil
}

type dispatcher struct {
	river.WorkerDefaults[DispatchArgs]
	pool *db.Pool
}

func (w *dispatcher) Work(ctx context.Context, _ *river.Job[DispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, ListDue, maxOrgsPerDispatch)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("retention: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: OrgArgs{Org: r.Org}})
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("retention: enqueue: %w", err)
	}
	return nil
}

// Register adds the retention workers to reg. r.App lists the due orgs.
func Register(reg *jobs.Registry, r *Remover) error {
	if err := jobs.Register[OrgArgs](reg, &orgWorker{r: r}); err != nil {
		return err
	}
	return jobs.Register[DispatchArgs](reg, &dispatcher{pool: r.App})
}

// PeriodicJobs returns the hourly dispatch.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(DispatchInterval),
			func() (river.JobArgs, *river.InsertOpts) { return DispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
}
