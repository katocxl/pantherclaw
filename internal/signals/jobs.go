// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package signals

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
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// JanitorInterval is how often received events past their 7 days are
// deleted. A replayed jti stays refused while its row is kept, and an iat
// older than 5 minutes is refused anyway.
const JanitorInterval = time.Hour

// lapsed records, once while it is open, that the receiver refuses events
// because the licence no longer includes Shared Signals.
func (s *Service) lapsed(ctx context.Context, org ids.OrgID) {
	if s.failures == nil {
		return
	}
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := s.failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
			Org: org, Kind: "signals.edition_lapsed",
			Summary:   "Shared Signals events are refused: the licence no longer includes them (Business edition).",
			NextStep:  "Renew a Business licence, or disable the transmitters and stop them sending.",
			DedupeKey: "signals.edition_lapsed",
		})
		return err
	})
	if err != nil {
		s.log.WarnContext(ctx, "signals.failure_report_failed", pclog.Err(err))
	}
}

// JanitorOrgArgs asks for one org's expired events to be deleted. Job args
// carry ids only (HR-056).
type JanitorOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (JanitorOrgArgs) Kind() string { return "signals.janitor_org" }

// InsertOpts keeps one queued job per org.
func (JanitorOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type janitorOrgWorker struct {
	river.WorkerDefaults[JanitorOrgArgs]
	pool *db.Pool
}

func (w *janitorOrgWorker) Work(ctx context.Context, job *river.Job[JanitorOrgArgs]) error {
	return w.pool.InTenantTx(ctx, job.Args.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).DeleteExpiredSSFEvents(ctx, job.Args.Org)
		return err
	})
}

// JanitorDispatchArgs fans the janitor out to every active org.
type JanitorDispatchArgs struct{}

// Kind implements river.JobArgs.
func (JanitorDispatchArgs) Kind() string { return "signals.janitor_dispatch" }

type janitorDispatchWorker struct {
	river.WorkerDefaults[JanitorDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054, D3).
func (w *janitorDispatchWorker) Work(ctx context.Context, _ *river.Job[JanitorDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("signals janitor dispatch: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: JanitorOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJanitor adds the janitor's workers to reg and returns its
// schedule.
func RegisterJanitor(reg *jobs.Registry, svc *Service) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[JanitorOrgArgs](reg, &janitorOrgWorker{pool: svc.pool}); err != nil {
		return nil, err
	}
	if err := jobs.Register[JanitorDispatchArgs](reg, &janitorDispatchWorker{pool: svc.pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(JanitorInterval),
			func() (river.JobArgs, *river.InsertOpts) { return JanitorDispatchArgs{}, nil }, nil),
	}, nil
}
