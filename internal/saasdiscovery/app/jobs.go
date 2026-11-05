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

// The daily SaaS and cloud agent runtime scans (G0 M34 D997), shaped as the
// GitHub daily org scans: an hourly dispatcher pages through the active
// orgs and enqueues one job per org, which starts each due schedule's scan.

// DailyScanEvery is how often the dispatcher runs; a schedule is due once
// ScheduleMinGap has passed since its last start.
const DailyScanEvery = time.Hour

// dispatchPageSize is how many orgs one lister page lists and one
// InsertMany enqueues.
const dispatchPageSize = 1000

// DailyScanOrgArgs asks for one org's due scheduled scans to be started.
type DailyScanOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (DailyScanOrgArgs) Kind() string { return "saas.daily_scans_org" }

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
	scheduler *Scheduler
}

func (w *dailyScanOrgWorker) Work(ctx context.Context, job *river.Job[DailyScanOrgArgs]) error {
	_, err := w.scheduler.RunOrg(ctx, job.Args.Org)
	return err
}

// DailyScanDispatchArgs asks for the daily-scan jobs of every active org.
type DailyScanDispatchArgs struct{}

// Kind implements river.JobArgs.
func (DailyScanDispatchArgs) Kind() string { return "saas.daily_scans_dispatch" }

type dailyScanDispatcher struct {
	river.WorkerDefaults[DailyScanDispatchArgs]
	pool *db.Pool
}

// Work lists the active orgs in pages through the audited lister (HR-054)
// and enqueues each page's jobs with one InsertMany.
func (w *dailyScanDispatcher) Work(ctx context.Context, _ *river.Job[DailyScanDispatchArgs]) error {
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("saas scans: %w", err)
	}
	return w.pool.CrossOrgPages(ctx, db.ListActiveOrgs, dispatchPageSize, func(page []db.OrgRef) error {
		params := make([]river.InsertManyParams, 0, len(page))
		for _, r := range page {
			params = append(params, river.InsertManyParams{Args: DailyScanOrgArgs{Org: r.Org}})
		}
		if _, err := client.InsertMany(ctx, params); err != nil {
			return fmt.Errorf("saas scans: enqueue: %w", err)
		}
		return nil
	})
}

// Register adds the daily-scan workers to reg.
func Register(reg *jobs.Registry, s *Scheduler) error {
	if err := jobs.Register[DailyScanOrgArgs](reg, &dailyScanOrgWorker{scheduler: s}); err != nil {
		return err
	}
	return jobs.Register[DailyScanDispatchArgs](reg, &dailyScanDispatcher{pool: s.Pool})
}

// PeriodicJobs returns the dispatcher's schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(DailyScanEvery),
			func() (river.JobArgs, *river.InsertOpts) { return DailyScanDispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
}
