// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sweep is the containment confirmation sweeper (G0 M10 D22,
// HR-249): a per-org job that re-reads each unsettled response action's
// paths, confirms what has evidence, and moves the action to the status its
// material paths give. A dispatcher fans it out to every active org every
// 2 seconds (D3); the per-org job exits early when nothing is unsettled.
package sweep

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// Interval is how often the sweep is dispatched (D22).
const Interval = 2 * time.Second

// maxPerSweep bounds one org's sweep; the next run takes the rest.
const maxPerSweep = 200

// Confirmer looks for confirmation evidence of an action's open paths and
// records it in tx (D22): a gateway path once that gateway acknowledged the
// action's epoch, a credential path once its revoke or rotate is recorded,
// an in-flight path once its transaction ended. A bypass route stays
// UNRESOLVED unless a credential path confirms it.
type Confirmer interface {
	Confirm(ctx context.Context, tx db.TenantTx, org ids.OrgID, action ids.UUID) error
}

// Settled is told, in the sweep's transaction, about an action that reached
// a final or partial status (FAILED raises a non-suppressible signal,
// HR-249).
type Settled interface {
	Settled(ctx context.Context, tx db.TenantTx, org ids.OrgID, action ids.UUID, status rdomain.Status) error
}

// Sweeper settles response actions.
type Sweeper struct {
	Pool *db.Pool
	// Confirm may be nil: then only recorded path states count.
	Confirm Confirmer
	// Notify may be nil.
	Notify Settled
}

// Sweep settles one org's unsettled actions and returns how many changed
// status.
func (s *Sweeper) Sweep(ctx context.Context, org ids.OrgID) (int, error) {
	n := 0
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		actions, err := pgresponse.Unsettled(ctx, tx, org, maxPerSweep)
		if err != nil || len(actions) == 0 {
			return err
		}
		for _, a := range actions {
			if s.Confirm != nil {
				if err := s.Confirm.Confirm(ctx, tx, org, a.ID); err != nil {
					return err
				}
			}
			paths, err := pgresponse.Paths(ctx, tx, org, a.ID)
			if err != nil {
				return err
			}
			cur, next := rdomain.Status(a.Status), rdomain.StatusOf(paths)
			if next == cur || next == rdomain.StatusRequested {
				continue
			}
			if err := pgresponse.Settle(ctx, tx, org, a.ID, cur, next, futureConfirmed(paths), a.HistoricalOpen); err != nil {
				return err
			}
			if s.Notify != nil {
				if err := s.Notify.Settled(ctx, tx, org, a.ID, next); err != nil {
					return err
				}
			}
			n++
		}
		return nil
	})
	return n, err
}

// futureConfirmed reports whether new access is stopped (F561): every
// material gateway path is confirmed. Historical exposure is reported
// separately.
func futureConfirmed(paths []rdomain.Path) bool {
	gateways := 0
	for _, p := range paths {
		if p.Type != rdomain.PathGateway || !p.Material {
			continue
		}
		if p.Status != rdomain.PathConfirmed {
			return false
		}
		gateways++
	}
	return gateways > 0
}

// OrgArgs asks for one org's actions to be swept. Job args carry ids only
// (HR-056).
type OrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (OrgArgs) Kind() string { return "response.sweep_org" }

// InsertOpts keeps one queued job per org.
func (OrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type orgWorker struct {
	river.WorkerDefaults[OrgArgs]
	s   *Sweeper
	log *slog.Logger
}

func (w *orgWorker) Work(ctx context.Context, job *river.Job[OrgArgs]) error {
	n, err := w.s.Sweep(ctx, job.Args.Org)
	if err == nil && n > 0 {
		w.log.InfoContext(ctx, "response.actions_settled", slog.String("org", job.Args.Org.String()), slog.Int("actions", n))
	}
	return err
}

// DispatchArgs fans the sweep out to every active org.
type DispatchArgs struct{}

// Kind implements river.JobArgs.
func (DispatchArgs) Kind() string { return "response.sweep_dispatch" }

type dispatchWorker struct {
	river.WorkerDefaults[DispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *dispatchWorker) Work(ctx context.Context, _ *river.Job[DispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("response sweep: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: OrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// Register adds the sweep's workers to reg and returns its schedule.
func Register(reg *jobs.Registry, s *Sweeper, log *slog.Logger) ([]*river.PeriodicJob, error) {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[OrgArgs](reg, &orgWorker{s: s, log: log}); err != nil {
		return nil, err
	}
	if err := jobs.Register[DispatchArgs](reg, &dispatchWorker{pool: s.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(Interval),
			func() (river.JobArgs, *river.InsertOpts) { return DispatchArgs{}, nil }, nil),
	}, nil
}
