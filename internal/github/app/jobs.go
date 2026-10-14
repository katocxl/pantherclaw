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

const maxOrgsPerDispatch = 1000

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
}

func (w *dailyScanDispatcher) Work(ctx context.Context, _ *river.Job[DailyScanDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, maxOrgsPerDispatch)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("github scans: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: DailyScanOrgArgs{Org: r.Org}})
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("github scans: enqueue: %w", err)
	}
	return nil
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
