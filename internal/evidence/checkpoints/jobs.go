// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package checkpoints

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// Jobs. A periodic dispatcher lists due orgs through the audited cross-org
// lister and enqueues one unique job per org (HR-054, HR-056: ids only);
// each job works in that org's tenant transactions.
const (
	// DefaultInterval is evidence.checkpoint_interval's default.
	DefaultInterval = 5 * time.Minute
	// IntegrityDispatchInterval is how often orgs due for their daily
	// verification are looked for.
	IntegrityDispatchInterval = time.Hour

	maxOrgsPerDispatch = 1000
	// maxCheckpointsPerJob bounds one job's backlog; the next dispatch
	// continues.
	maxCheckpointsPerJob = 16
	checkpointTimeout    = 5 * time.Minute
	// verifyTimeout stays below River's stuck-job rescue (10 minutes).
	verifyTimeout = 9 * time.Minute
)

var uniqueWhileQueued = river.UniqueOpts{
	ByArgs: true,
	ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	},
}

// CheckpointOrgArgs asks for one org's checkpoints.
type CheckpointOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (CheckpointOrgArgs) Kind() string { return "evidence.checkpoint_org" }

// InsertOpts makes the job unique per org while queued or running.
func (CheckpointOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: uniqueWhileQueued}
}

// VerifyOrgArgs asks for one org's daily verification.
type VerifyOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (VerifyOrgArgs) Kind() string { return "evidence.verify_org" }

// InsertOpts makes the job unique per org while queued or running.
func (VerifyOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: uniqueWhileQueued}
}

// CheckpointDispatchArgs asks for checkpoint jobs for every due org.
type CheckpointDispatchArgs struct{}

// Kind implements river.JobArgs.
func (CheckpointDispatchArgs) Kind() string { return "evidence.checkpoint_dispatch" }

// VerifyDispatchArgs asks for verification jobs for every due org.
type VerifyDispatchArgs struct{}

// Kind implements river.JobArgs.
func (VerifyDispatchArgs) Kind() string { return "evidence.verify_dispatch" }

type checkpointWorker struct {
	river.WorkerDefaults[CheckpointOrgArgs]
	svc *Service
}

func (w *checkpointWorker) Timeout(*river.Job[CheckpointOrgArgs]) time.Duration {
	return checkpointTimeout
}

// Work checkpoints until the org is caught up; an integrity failure was
// reported and ends the job without a retry.
func (w *checkpointWorker) Work(ctx context.Context, job *river.Job[CheckpointOrgArgs]) error {
	for range maxCheckpointsPerJob {
		res, err := w.svc.Checkpoint(ctx, job.Args.Org)
		var ie *IntegrityError
		if errors.As(err, &ie) {
			return nil
		}
		if err != nil || !res.Signed {
			return err
		}
	}
	return nil
}

type verifyWorker struct {
	river.WorkerDefaults[VerifyOrgArgs]
	svc *Service
}

func (w *verifyWorker) Timeout(*river.Job[VerifyOrgArgs]) time.Duration { return verifyTimeout }

func (w *verifyWorker) Work(ctx context.Context, job *river.Job[VerifyOrgArgs]) error {
	_, err := w.svc.Verify(ctx, job.Args.Org)
	var ie *IntegrityError
	if errors.As(err, &ie) {
		return nil
	}
	return err
}

type dispatcher[T river.JobArgs] struct {
	river.WorkerDefaults[T]
	pool    *db.Pool
	purpose db.ListerPurpose
	job     func(ids.OrgID) river.JobArgs
}

func (w *dispatcher[T]) Work(ctx context.Context, _ *river.Job[T]) error {
	refs, err := w.pool.CrossOrgList(ctx, w.purpose, maxOrgsPerDispatch)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("checkpoints: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: w.job(r.Org)})
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("checkpoints: enqueue: %w", err)
	}
	return nil
}

// Register adds the checkpoint and verification workers to reg.
func Register(reg *jobs.Registry, svc *Service) error {
	if err := jobs.Register[CheckpointOrgArgs](reg, &checkpointWorker{svc: svc}); err != nil {
		return err
	}
	if err := jobs.Register[VerifyOrgArgs](reg, &verifyWorker{svc: svc}); err != nil {
		return err
	}
	if err := jobs.Register[CheckpointDispatchArgs](reg, &dispatcher[CheckpointDispatchArgs]{
		pool: svc.Pool, purpose: db.ListCheckpointsDue, job: func(o ids.OrgID) river.JobArgs { return CheckpointOrgArgs{Org: o} },
	}); err != nil {
		return err
	}
	return jobs.Register[VerifyDispatchArgs](reg, &dispatcher[VerifyDispatchArgs]{
		pool: svc.Pool, purpose: db.ListIntegrityDue, job: func(o ids.OrgID) river.JobArgs { return VerifyOrgArgs{Org: o} },
	})
}

// PeriodicJobs returns the dispatcher schedules: checkpoints every
// interval (evidence.checkpoint_interval), verification every hour for the
// orgs not verified in the last day.
func PeriodicJobs(interval time.Duration) []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(interval),
			func() (river.JobArgs, *river.InsertOpts) { return CheckpointDispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
		river.NewPeriodicJob(river.PeriodicInterval(IntegrityDispatchInterval),
			func() (river.JobArgs, *river.InsertOpts) { return VerifyDispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
}
