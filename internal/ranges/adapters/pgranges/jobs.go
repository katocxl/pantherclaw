// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgranges

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
)

// AbandonInterval is how often running ranges past 24 hours are abandoned.
const AbandonInterval = 10 * time.Minute

// maxAbandonedPerRun bounds one org's sweep; the next run takes the rest.
const maxAbandonedPerRun = 500

// sweeper is the audit actor of the abandon sweep.
var sweeper = evdomain.Actor{Type: "system", ID: "range-abandon"}

// Abandoner abandons the ranges nobody finished.
type Abandoner struct{ Pool *db.Pool }

// AbandonStale marks an org's ranges still running after 24 hours as
// ABANDONED, once each, and audits it. An abandoned range holds no MISSING
// results and cannot be a baseline or exported: a run that never finished
// says nothing about its scenarios. It returns how many it abandoned.
func (a Abandoner) AbandonStale(ctx context.Context, org ids.OrgID) (int, error) {
	n := 0
	err := a.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		stale, err := q.StaleRedteamRuns(ctx, org, maxAbandonedPerRun)
		if err != nil {
			return err
		}
		for _, r := range stale {
			if _, err := q.TransitionRedteamRun(ctx, string(domain.Abandoned), org, r.ID); err != nil && !db.IsNoRows(err) {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "redteam.range_abandoned", Actor: sweeper, Outcome: audit.Success,
				Object: &audit.Object{Type: "redteam_range", ID: r.ID.String()}, Details: map[string]string{"agent_id": r.RangeAgentID.String()},
			}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// AbandonOrgArgs asks for one org's stale ranges to be abandoned. Job args
// carry ids only (HR-056).
type AbandonOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (AbandonOrgArgs) Kind() string { return "redteam.abandon_org" }

// InsertOpts keeps one queued job per org.
func (AbandonOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type abandonOrgWorker struct {
	river.WorkerDefaults[AbandonOrgArgs]
	a   Abandoner
	log *slog.Logger
}

func (w *abandonOrgWorker) Work(ctx context.Context, job *river.Job[AbandonOrgArgs]) error {
	n, err := w.a.AbandonStale(ctx, job.Args.Org)
	if err == nil && n > 0 {
		w.log.InfoContext(ctx, "redteam.ranges_abandoned", slog.String("org", job.Args.Org.String()), slog.Int("ranges", n))
	}
	return err
}

// AbandonDispatchArgs fans the abandon sweep out to every active org.
type AbandonDispatchArgs struct{}

// Kind implements river.JobArgs.
func (AbandonDispatchArgs) Kind() string { return "redteam.abandon_dispatch" }

type abandonDispatchWorker struct {
	river.WorkerDefaults[AbandonDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *abandonDispatchWorker) Work(ctx context.Context, _ *river.Job[AbandonDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("range abandon: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: AbandonOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterAbandon adds the abandon sweep's workers to reg and returns its
// schedule.
func RegisterAbandon(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) ([]*river.PeriodicJob, error) {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[AbandonOrgArgs](reg, &abandonOrgWorker{a: Abandoner{Pool: pool}, log: log}); err != nil {
		return nil, err
	}
	if err := jobs.Register[AbandonDispatchArgs](reg, &abandonDispatchWorker{pool: pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(AbandonInterval),
			func() (river.JobArgs, *river.InsertOpts) { return AbandonDispatchArgs{}, nil }, nil),
	}, nil
}
