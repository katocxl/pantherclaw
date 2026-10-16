// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// The derived automation exceptions (D38): a gate past half its deadline
// (gate_stalled) and three consecutive FAILED executions (recovery_failed)
// are owned failures routed to the automation's owner, found by a per-org
// sweep. The other D38 kinds are raised where they happen.

// SweepInterval is how often the sweep runs.
const SweepInterval = 5 * time.Minute

// FailureSink records owned failures (reflex/failures.Sink).
type FailureSink interface {
	ReportTx(ctx context.Context, tx db.TenantTx, f reflexdomain.Failure) (ids.UUID, bool, error)
}

// Sweep raises the derived exceptions of one org and returns how many it
// recorded (a failure already open is counted once, deduplicated).
func Sweep(ctx context.Context, pool *db.Pool, sink FailureSink, org ids.OrgID) (int, error) {
	n := 0
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		gates, err := q.AssuranceStalledGates(ctx, org)
		if err != nil {
			return err
		}
		for _, g := range gates {
			owner := reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: g.OwnerUserID.String()}
			if _, _, err := sink.ReportTx(ctx, tx, reflexdomain.Failure{
				Org: org, Kind: FailureGateStalled, DedupeKey: FailureGateStalled + ":" + g.ID.String(),
				Summary:  fmt.Sprintf("A gate of automation %s is past half its deadline without a decision.", g.Name),
				NextStep: "Ask an eligible approver to decide it, or cancel the execution.",
				Scope: []reflexdomain.Subject{
					{Type: reflexdomain.SubjectAutomation, ID: g.AutomationID.String()},
					{Type: reflexdomain.SubjectAutomationExecution, ID: g.ExecutionID.String()},
				},
				Owner: &owner, Deadline: g.DeadlineAt,
			}); err != nil {
				return err
			}
			n++
		}
		failing, err := q.AssuranceFailingAutomations(ctx, org)
		if err != nil {
			return err
		}
		for _, a := range failing {
			owner := reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: a.OwnerUserID.String()}
			if _, _, err := sink.ReportTx(ctx, tx, reflexdomain.Failure{
				Org: org, Kind: FailureRecoveryFailed, DedupeKey: FailureRecoveryFailed + ":" + a.ID.String(),
				Summary:  fmt.Sprintf("Automation %s failed %d times in a row.", a.Name, RecoveryFailedRun),
				NextStep: "Inspect the latest execution; pause the automation until the cause is fixed.",
				Scope: []reflexdomain.Subject{
					{Type: reflexdomain.SubjectAutomation, ID: a.ID.String()},
					{Type: reflexdomain.SubjectAutomationExecution, ID: a.ExecutionID.String()},
				},
				Owner: &owner,
			}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// SweepArgs sweeps one org; ids only (HR-056).
type SweepArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SweepArgs) Kind() string { return "automation_assurance_sweep" }

// InsertOpts keeps one queued sweep per org.
func (SweepArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// SweepDispatchArgs fans the sweep out to every active org.
type SweepDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SweepDispatchArgs) Kind() string { return "automation_assurance_sweep_dispatch" }

type sweepWorker struct {
	river.WorkerDefaults[SweepArgs]
	pool *db.Pool
	sink FailureSink
}

func (w *sweepWorker) Work(ctx context.Context, job *river.Job[SweepArgs]) error {
	_, err := Sweep(ctx, w.pool, w.sink, job.Args.Org)
	return err
}

type sweepDispatchWorker struct {
	river.WorkerDefaults[SweepDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one
// sweep per org.
func (w *sweepDispatchWorker) Work(ctx context.Context, _ *river.Job[SweepDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("automation assurance sweep: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SweepArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterSweep adds the sweep workers and returns their schedule.
func RegisterSweep(reg *jobs.Registry, pool *db.Pool, sink FailureSink) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[SweepArgs](reg, &sweepWorker{pool: pool, sink: sink}); err != nil {
		return nil, err
	}
	if err := jobs.Register[SweepDispatchArgs](reg, &sweepDispatchWorker{pool: pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepDispatchArgs{}, nil }, nil),
	}, nil
}
