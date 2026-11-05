// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package federationkeys

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
)

// The daily refresh (D1021): every hour, per org, each trust not refreshed
// for RefreshEvery re-reads its peer's document; a trust whose document
// expired and could not be refreshed goes STALE. The same job deletes
// expired replay ids and old call records.

// JobInterval is how often the refresh dispatch runs.
const JobInterval = time.Hour

// RefreshOrgArgs asks for one org's due trusts to be refreshed (ids only,
// HR-056).
type RefreshOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (RefreshOrgArgs) Kind() string { return "federation.refresh_org" }

// InsertOpts keeps one queued job per org.
func (RefreshOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type refreshOrgWorker struct {
	river.WorkerDefaults[RefreshOrgArgs]
	svc *Service
	log *slog.Logger
}

func (w *refreshOrgWorker) Work(ctx context.Context, job *river.Job[RefreshOrgArgs]) error {
	if err := w.svc.SweepOrg(ctx, job.Args.Org); err != nil {
		return err
	}
	n, err := w.svc.RefreshOrg(ctx, job.Args.Org)
	if n > 0 {
		w.log.InfoContext(ctx, "federation.trusts_refreshed", slog.String("org", job.Args.Org.String()), slog.Int("trusts", n))
	}
	return err
}

// RefreshDispatchArgs fans the refresh out to every active org.
type RefreshDispatchArgs struct{}

// Kind implements river.JobArgs.
func (RefreshDispatchArgs) Kind() string { return "federation.refresh_dispatch" }

type refreshDispatchWorker struct {
	river.WorkerDefaults[RefreshDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *refreshDispatchWorker) Work(ctx context.Context, _ *river.Job[RefreshDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("federation refresh: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		if r.Org == ids.PlatformOrg {
			continue
		}
		params = append(params, river.InsertManyParams{Args: RefreshOrgArgs{Org: r.Org}})
	}
	if len(params) == 0 {
		return nil
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJobs adds the refresh workers to reg.
func RegisterJobs(reg *jobs.Registry, pool *db.Pool, svc *Service, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[RefreshOrgArgs](reg, &refreshOrgWorker{svc: svc, log: log}); err != nil {
		return err
	}
	return jobs.Register[RefreshDispatchArgs](reg, &refreshDispatchWorker{pool: pool})
}

// PeriodicJobs returns the refresh schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(JobInterval),
			func() (river.JobArgs, *river.InsertOpts) { return RefreshDispatchArgs{}, nil }, nil),
	}
}
