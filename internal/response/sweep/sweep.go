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

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
)

// Interval is how often the sweep is dispatched (D22).
const Interval = 2 * time.Second

// maxPerSweep bounds one org's sweep; the next run takes the rest.
const maxPerSweep = 200

// Advancer looks for confirmation evidence of an unsettled action's open
// paths in tx (a gateway path once its gateway was sent the action's epoch, a
// credential or bypass path once the credential changed, an in-flight path
// once its dispatch ended) and moves the action to the status its material
// paths give, telling the org about PARTIAL and FAILED (HR-249). It reports
// whether the status changed.
type Advancer interface {
	Advance(ctx context.Context, tx db.TenantTx, a dbq.PcResponseAction) (bool, error)
	// ProposeExpiredIn drafts restoration plans for controls past their
	// expiry (D54); it never lifts one.
	ProposeExpiredIn(ctx context.Context, tx db.TenantTx) (int, error)
}

// Sweeper settles response actions.
type Sweeper struct {
	Pool    *db.Pool
	Advance Advancer
}

// Sweep settles one org's unsettled actions and returns how many changed
// status.
func (s *Sweeper) Sweep(ctx context.Context, org ids.OrgID) (int, error) {
	n := 0
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := s.Advance.ProposeExpiredIn(ctx, tx); err != nil {
			return err
		}
		actions, err := pgresponse.Unsettled(ctx, tx, org, maxPerSweep)
		if err != nil || len(actions) == 0 {
			return err
		}
		for _, a := range actions {
			changed, err := s.Advance.Advance(ctx, tx, a)
			if err != nil {
				return err
			}
			if changed {
				n++
			}
		}
		return nil
	})
	return n, err
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
