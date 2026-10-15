// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package operations

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

// MetricsInterval is how often the metrics dispatcher runs. A collection
// is idempotent per hour, so running more often than hourly only fills a
// missed hour sooner.
const MetricsInterval = 15 * time.Minute

// MetricsOrgArgs asks for one org's metric samples. Job args carry ids only
// (HR-056).
type MetricsOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (MetricsOrgArgs) Kind() string { return "operations.metrics_org" }

// InsertOpts keeps one queued job per org (D3).
func (MetricsOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type metricsWorker struct {
	river.WorkerDefaults[MetricsOrgArgs]
	c   *Collector
	log *slog.Logger
}

func (w *metricsWorker) Work(ctx context.Context, job *river.Job[MetricsOrgArgs]) error {
	n, err := w.c.Collect(ctx, job.Args.Org)
	if err == nil && n > 0 {
		w.log.InfoContext(ctx, "operations.metrics_sampled", slog.String("org", job.Args.Org.String()), slog.Int("samples", n))
	}
	return err
}

// MetricsDispatchArgs fans the collection out to every active org.
type MetricsDispatchArgs struct{}

// Kind implements river.JobArgs.
func (MetricsDispatchArgs) Kind() string { return "operations.metrics_dispatch" }

type metricsDispatcher struct {
	river.WorkerDefaults[MetricsDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org (D3).
func (w *metricsDispatcher) Work(ctx context.Context, _ *river.Job[MetricsDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("operations metrics: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: MetricsOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterMetrics adds the metrics workers to reg and returns the schedule.
func RegisterMetrics(reg *jobs.Registry, c *Collector, log *slog.Logger) ([]*river.PeriodicJob, error) {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[MetricsOrgArgs](reg, &metricsWorker{c: c, log: log}); err != nil {
		return nil, err
	}
	if err := jobs.Register[MetricsDispatchArgs](reg, &metricsDispatcher{pool: c.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(MetricsInterval),
			func() (river.JobArgs, *river.InsertOpts) { return MetricsDispatchArgs{}, nil }, nil),
	}, nil
}
