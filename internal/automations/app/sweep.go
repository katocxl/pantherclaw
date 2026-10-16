// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// The ceiling sweep (D7, D54, D57): per org every 5 minutes over the
// ACTIVE ceilings. A ceiling past its review date EXPIRES and its
// automation pauses (CEILING_EXPIRED); one whose approver no longer
// qualifies is VOID (CEILING_VOID). Both report an owned failure to the
// owner. A ceiling whose review date is 7 days or 1 day away reports an
// automation.review_due failure once per window. Correctness never depends
// on the sweep: issuance checks the same at use (HR-273).

// SweepInterval is how often the sweep runs.
const SweepInterval = 5 * time.Minute

// SweptCeilings counts what one org's sweep changed.
type SweptCeilings struct{ Expired, Voided, ReviewDue int }

// SweepOrg sweeps one org's ceilings; each change runs in its own
// transaction.
func (s *Service) SweepOrg(ctx context.Context, org ids.OrgID) (SweptCeilings, error) {
	var out SweptCeilings
	var rows []dbq.ActiveAutomationCeilingsRow
	if err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		rows, err = dbq.New(tx).ActiveAutomationCeilings(ctx, org)
		return err
	}, db.ReadOnly()); err != nil {
		return out, err
	}
	// One ceiling's error never stops the others (D91): it is reported
	// to the owner and returned, so the job retries.
	var errs []error
	for _, c := range rows {
		if err := s.sweepCeiling(ctx, org, c, &out); err != nil {
			errs = append(errs, fmt.Errorf("ceiling %s: %w", c.ID, err))
			if ferr := s.sweepFailed(ctx, org, c); ferr != nil {
				errs = append(errs, ferr)
			}
		}
	}
	return out, errors.Join(errs...)
}

func (s *Service) sweepCeiling(ctx context.Context, org ids.OrgID, c dbq.ActiveAutomationCeilingsRow, out *SweptCeilings) error {
	if c.Due {
		if err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return s.endCeilingTx(ctx, tx, org, c.ID, autodomain.CeilingExpired, "REVIEW_DATE", autodomain.PauseCeilingExpired)
		}); err != nil {
			return err
		}
		out.Expired++
		return nil
	}
	var ok bool
	var reason string
	if err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		ok, reason, err = s.Check(ctx, tx.Pgx(), autodomain.CeilingCheck{
			Org: org, Automation: c.AutomationID, Ceiling: c.ID, Approvers: c.ApprovedBy,
		})
		return err
	}, db.ReadOnly()); err != nil {
		return err
	}
	if !ok {
		if err := s.VoidCeiling(ctx, org, c.ID, reason); err != nil {
			return err
		}
		out.Voided++
		return nil
	}
	if n, err := s.reviewDue(ctx, org, c); err != nil {
		return err
	} else if n {
		out.ReviewDue++
	}
	return nil
}

// sweepFailed tells the owner that the automation's authority could not
// be checked (once per ceiling until it is resolved).
func (s *Service) sweepFailed(ctx context.Context, org ids.OrgID, c dbq.ActiveAutomationCeilingsRow) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		a, err := loadAutomation(ctx, dbq.New(tx), org, c.AutomationID, false)
		if err != nil {
			return err
		}
		return s.failure(ctx, tx, a, FailureSweep,
			"The scheduled check of automation "+a.Name+"'s authority failed; it is retried every 5 minutes.",
			"If this stays open, ask an administrator to look at the server's logs.", "sweep:"+c.ID.String())
	})
}

// reviewDue reports automation.review_due 7 days and 1 day before the
// review date, once per window (the failure's dedupe key).
func (s *Service) reviewDue(ctx context.Context, org ids.OrgID, c dbq.ActiveAutomationCeilingsRow) (bool, error) {
	left := time.Until(c.ReviewBy)
	window := ""
	switch {
	case left <= 24*time.Hour:
		window = "1d"
	case left <= 7*24*time.Hour:
		window = "7d"
	default:
		return false, nil
	}
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		a, err := loadAutomation(ctx, dbq.New(tx), org, c.AutomationID, false)
		if err != nil {
			return err
		}
		return s.failure(ctx, tx, a, FailureReviewDue,
			fmt.Sprintf("Automation %s reaches its review date on %s; it pauses then.", a.Name, c.ReviewBy.UTC().Format(time.DateOnly)),
			"Review the automation and enable a version with a new review date.", "review:"+c.ID.String()+":"+window)
	})
	return err == nil, err
}

// SweepOrgArgs asks for one org's ceilings to be swept (ids only, HR-056).
type SweepOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SweepOrgArgs) Kind() string { return "automations.ceiling_sweep_org" }

// InsertOpts keeps one queued job per org.
func (SweepOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type sweepOrgWorker struct {
	river.WorkerDefaults[SweepOrgArgs]
	svc *Service
	log *slog.Logger
}

func (w *sweepOrgWorker) Work(ctx context.Context, job *river.Job[SweepOrgArgs]) error {
	out, err := w.svc.SweepOrg(ctx, job.Args.Org)
	if out.Expired+out.Voided+out.ReviewDue > 0 {
		w.log.InfoContext(ctx, "automations.ceiling_sweep", slog.String("org", job.Args.Org.String()),
			slog.Int("expired", out.Expired), slog.Int("voided", out.Voided), slog.Int("review_due", out.ReviewDue))
	}
	return err
}

// SweepDispatchArgs fans the sweep out to every active org.
type SweepDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SweepDispatchArgs) Kind() string { return "automations.ceiling_sweep_dispatch" }

type sweepDispatchWorker struct {
	river.WorkerDefaults[SweepDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054, purpose "orgs",
// D13) and enqueues one job per org.
func (w *sweepDispatchWorker) Work(ctx context.Context, _ *river.Job[SweepDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("automations sweep: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SweepOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJobs adds the sweep workers to reg.
func (s *Service) RegisterJobs(reg *jobs.Registry, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[SweepOrgArgs](reg, &sweepOrgWorker{svc: s, log: log}); err != nil {
		return err
	}
	return jobs.Register[SweepDispatchArgs](reg, &sweepDispatchWorker{pool: s.Pool})
}

// PeriodicJobs returns the sweep schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepDispatchArgs{}, nil }, nil),
	}
}
