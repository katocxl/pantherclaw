// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

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

// DailyScanEvery is how often the dispatcher looks for GitHub App
// connections due their daily org scan; a connection is due once a day.
const DailyScanEvery = time.Hour

// dispatchPageSize is how many orgs one lister page of the daily-scan
// dispatcher lists and one InsertMany enqueues; the dispatcher pages
// through every active org (D45).
const dispatchPageSize = 1000

// DailyScanOrgArgs asks for one org's daily org scans to be scheduled.
type DailyScanOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (DailyScanOrgArgs) Kind() string { return "github.daily_scans_org" }

// InsertOpts keeps one job per org queued or running.
func (DailyScanOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type dailyScanOrgWorker struct {
	river.WorkerDefaults[DailyScanOrgArgs]
	scans *Scans
}

func (w *dailyScanOrgWorker) Work(ctx context.Context, job *river.Job[DailyScanOrgArgs]) error {
	_, err := w.scans.ScheduleDaily(ctx, job.Args.Org)
	return err
}

// DailyScanDispatchArgs asks for the daily-scan jobs of every active org.
type DailyScanDispatchArgs struct{}

// Kind implements river.JobArgs.
func (DailyScanDispatchArgs) Kind() string { return "github.daily_scans_dispatch" }

type dailyScanDispatcher struct {
	river.WorkerDefaults[DailyScanDispatchArgs]
	pool *db.Pool
	// pageSize is the lister page size and so the bound of one InsertMany;
	// zero means dispatchPageSize. insert enqueues one page; nil means the
	// River client of the job's context. Tests set both.
	pageSize int
	insert   func(ctx context.Context, params []river.InsertManyParams) error
}

// Work lists the active orgs in pages through the audited lister (HR-054,
// D45) and enqueues each page's scans with one InsertMany, so no insert
// is larger than a page.
func (w *dailyScanDispatcher) Work(ctx context.Context, _ *river.Job[DailyScanDispatchArgs]) error {
	insert := w.insert
	if insert == nil {
		client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
		if err != nil {
			return fmt.Errorf("github scans: %w", err)
		}
		insert = func(ctx context.Context, params []river.InsertManyParams) error {
			_, err := client.InsertMany(ctx, params)
			return err
		}
	}
	size := w.pageSize
	if size == 0 {
		size = dispatchPageSize
	}
	return w.pool.CrossOrgPages(ctx, db.ListActiveOrgs, size, func(page []db.OrgRef) error {
		params := make([]river.InsertManyParams, 0, len(page))
		for _, r := range page {
			params = append(params, river.InsertManyParams{Args: DailyScanOrgArgs{Org: r.Org}})
		}
		if err := insert(ctx, params); err != nil {
			return fmt.Errorf("github scans: enqueue: %w", err)
		}
		return nil
	})
}

// Register adds the daily-scan workers to reg.
func Register(reg *jobs.Registry, scans *Scans) error {
	if err := jobs.Register[DailyScanOrgArgs](reg, &dailyScanOrgWorker{scans: scans}); err != nil {
		return err
	}
	return jobs.Register[DailyScanDispatchArgs](reg, &dailyScanDispatcher{pool: scans.Pool})
}

// PeriodicJobs returns the daily-scan dispatcher's schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(DailyScanEvery),
			func() (river.JobArgs, *river.InsertOpts) { return DailyScanDispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
}
