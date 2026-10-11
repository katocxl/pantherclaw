// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchoring

import (
	"context"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// TickInterval is how often the worker looks for an anchor to create or
// one whose backoff is over; the anchoring period itself is
// evidence.anchoring.interval.
const TickInterval = time.Minute

// tickTimeout stays below River's stuck-job rescue (10 minutes) while
// allowing a few slow log answers.
const tickTimeout = 9 * time.Minute

// TickArgs asks for one anchoring tick. It carries no data (HR-056).
type TickArgs struct{}

// Kind implements river.JobArgs.
func (TickArgs) Kind() string { return "evidence.anchor_tick" }

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

func (w *tickWorker) Timeout(*river.Job[TickArgs]) time.Duration { return tickTimeout }

func (w *tickWorker) Work(ctx context.Context, _ *river.Job[TickArgs]) error { return w.svc.Tick(ctx) }

// Register adds the anchoring worker to reg.
func Register(reg *jobs.Registry, svc *Service) error {
	return jobs.Register[TickArgs](reg, &tickWorker{svc: svc})
}

// PeriodicJobs returns the tick's schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(TickInterval),
			func() (river.JobArgs, *river.InsertOpts) { return TickArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
}
