// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

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

const (
	// SweepInterval is how often orgs with open permits are found.
	SweepInterval    = time.Second
	maxOrgsPerSweep  = 1000
	listPermitsSweep = db.ListerPurpose("permits_sweep")
	// listBudgetSettle finds orgs with settled reservations not yet applied
	// to their budget rows (ADR-0015).
	listBudgetSettle = db.ListerPurpose("budget_settle")
)

// SweepOrgArgs asks for one org's permits to be swept (HR-003).
type SweepOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SweepOrgArgs) Kind() string { return "authority.sweep_org" }

// InsertOpts makes sweep jobs unique per org while queued or running.
func (SweepOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// SweepOrgWorker sweeps one org.
type SweepOrgWorker struct {
	river.WorkerDefaults[SweepOrgArgs]
	Service    *Service
	StaleAfter time.Duration
}

// Work implements river.Worker.
func (w *SweepOrgWorker) Work(ctx context.Context, job *river.Job[SweepOrgArgs]) error {
	_, err := w.Service.SweepOrg(ctx, job.Args.Org, w.StaleAfter)
	return err
}

// SweepDispatchArgs asks for sweep jobs for every org with open permits.
type SweepDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SweepDispatchArgs) Kind() string { return "authority.sweep_dispatch" }

// SweepDispatchWorker finds orgs via the audited lister (HR-054): those
// with permits to sweep and those with settlements to apply.
type SweepDispatchWorker struct {
	river.WorkerDefaults[SweepDispatchArgs]
	Pool *db.Pool
}

// Work implements river.Worker.
func (w *SweepDispatchWorker) Work(ctx context.Context, _ *river.Job[SweepDispatchArgs]) error {
	var refs []db.OrgRef
	seen := map[ids.OrgID]bool{}
	for _, purpose := range []db.ListerPurpose{listPermitsSweep, listBudgetSettle} {
		found, err := w.Pool.CrossOrgList(ctx, purpose, maxOrgsPerSweep)
		if err != nil {
			return err
		}
		for _, r := range found {
			if !seen[r.Org] {
				seen[r.Org] = true
				refs = append(refs, r)
			}
		}
	}
	if len(refs) == 0 {
		return nil
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("authority: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SweepOrgArgs{Org: r.Org}})
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("authority: enqueue sweeps: %w", err)
	}
	return nil
}

// RegisterSweeper adds the sweeper workers to reg.
func RegisterSweeper(reg *jobs.Registry, pool *db.Pool, svc *Service, staleAfter time.Duration) error {
	if staleAfter <= 0 {
		staleAfter = DefaultStaleDispatch
	}
	if err := jobs.Register[SweepOrgArgs](reg, &SweepOrgWorker{Service: svc, StaleAfter: staleAfter}); err != nil {
		return err
	}
	return jobs.Register[SweepDispatchArgs](reg, &SweepDispatchWorker{Pool: pool})
}

// SweeperPeriodicJobs returns the sweep dispatcher schedule.
func SweeperPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(
			river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepDispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true},
		),
	}
}
