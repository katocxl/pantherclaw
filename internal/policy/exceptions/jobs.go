// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exceptions

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// SweepInterval is how often exceptions are swept. An exception past its
// expiry waives nothing whether or not the sweep has run: the Authority
// reads only those whose expiry the database clock has not passed.
const SweepInterval = 5 * time.Minute

// ExpiringWithin is how long before its expiry an exception's owner is told
// (D14: 24 hours).
const ExpiringWithin = 24 * time.Hour

// maxPerSweep bounds one org's sweep; the next run takes the rest.
const maxPerSweep = 500

// Sweep records the org's exceptions past their expiry as EXPIRED,
// declines pending ones whose change request ended unapproved, and tells the owners of active ones that end within a day, once each. It
// returns how many it expired.
func (s *Service) Sweep(ctx context.Context, org ids.OrgID) (int, error) {
	n := 0
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		expired, err := q.ExpirePolicyExceptions(ctx, org, maxPerSweep)
		if err != nil {
			return err
		}
		for _, x := range expired {
			if err := s.audit(ctx, tx, system, x, "policy.exception_expired", nil); err != nil {
				return err
			}
		}
		n = len(expired)
		declined, err := q.DeclineEndedPolicyExceptions(ctx, org, maxPerSweep)
		if err != nil {
			return err
		}
		for _, x := range declined {
			if err := s.audit(ctx, tx, system, x, "policy.exception_declined", nil); err != nil {
				return err
			}
		}
		expiring, err := q.ExpiringPolicyExceptions(ctx, org, int64(ExpiringWithin/time.Second), maxPerSweep)
		if err != nil {
			return err
		}
		for _, x := range expiring {
			if err := s.notify(ctx, tx, x, "policy.exception_expiring", "policy.exception_expiring:"+x.ID.String()); err != nil {
				return err
			}
		}
		return nil
	})
	return n, err
}

// SweepOrgArgs asks for one org's exceptions to be swept. Job args carry
// ids only (HR-056).
type SweepOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SweepOrgArgs) Kind() string { return "policy.exception_sweep_org" }

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
	n, err := w.svc.Sweep(ctx, job.Args.Org)
	if err == nil && n > 0 {
		w.log.InfoContext(ctx, "policy.exceptions_expired", slog.String("org", job.Args.Org.String()), slog.Int("exceptions", n))
	}
	return err
}

// SweepDispatchArgs fans the sweep out to every active org.
type SweepDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SweepDispatchArgs) Kind() string { return "policy.exception_sweep_dispatch" }

type sweepDispatchWorker struct {
	river.WorkerDefaults[SweepDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *sweepDispatchWorker) Work(ctx context.Context, _ *river.Job[SweepDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("policy exception sweep: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SweepOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterSweep adds the sweep's workers to reg and returns its schedule.
func RegisterSweep(reg *jobs.Registry, svc *Service, log *slog.Logger) ([]*river.PeriodicJob, error) {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[SweepOrgArgs](reg, &sweepOrgWorker{svc: svc, log: log}); err != nil {
		return nil, err
	}
	if err := jobs.Register[SweepDispatchArgs](reg, &sweepDispatchWorker{pool: svc.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepDispatchArgs{}, nil }, nil),
	}, nil
}
