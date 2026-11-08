// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package globallog

import (
	"context"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// TickArgs asks for one append-and-witness tick. It carries no data (HR-056).
type TickArgs struct{}

// Kind implements river.JobArgs.
func (TickArgs) Kind() string { return "evidence.global_log_tick" }

// InsertOpts keeps one tick queued or running at a time.
func (TickArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type tickWorker struct {
	river.WorkerDefaults[TickArgs]
	svc *Service
}

// Timeout stays below River's stuck-job rescue (10 minutes).
func (w *tickWorker) Timeout(*river.Job[TickArgs]) time.Duration { return tickTimeoutAllowance }

func (w *tickWorker) Work(ctx context.Context, _ *river.Job[TickArgs]) error { return w.svc.Tick(ctx) }

// Register adds the root log's worker to reg.
func Register(reg *jobs.Registry, svc *Service) error {
	return jobs.Register[TickArgs](reg, &tickWorker{svc: svc})
}

// PeriodicJobs returns the tick's schedule: every five minutes, well within
// the shortest anchoring period.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(defaultTickInterval),
			func() (river.JobArgs, *river.InsertOpts) { return TickArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
}
