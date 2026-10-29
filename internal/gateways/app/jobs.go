// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

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

// Housekeeping of gateway status and shared MCP state (G0 M15 D11, D12):
// gateway_replicas.prune runs hourly and deletes replicas not seen for 24
// hours; gateway_mcp_state.purge runs every minute and deletes expired MCP
// state. Each fans out to one job per active org (ids only, HR-056).
const (
	PruneInterval = time.Hour
	PurgeInterval = time.Minute
)

var uniqueQueued = river.InsertOpts{UniqueOpts: river.UniqueOpts{
	ByArgs: true,
	ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	},
}}

// PruneReplicasArgs fans the replica prune out to every active org.
type PruneReplicasArgs struct{}

// Kind implements river.JobArgs.
func (PruneReplicasArgs) Kind() string { return "gateway_replicas.prune" }

// PruneReplicasOrgArgs prunes one org's replicas.
type PruneReplicasOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (PruneReplicasOrgArgs) Kind() string { return "gateway_replicas.prune_org" }

// InsertOpts keeps one queued job per org.
func (PruneReplicasOrgArgs) InsertOpts() river.InsertOpts { return uniqueQueued }

// PurgeMCPStateArgs fans the MCP state purge out to every active org.
type PurgeMCPStateArgs struct{}

// Kind implements river.JobArgs.
func (PurgeMCPStateArgs) Kind() string { return "gateway_mcp_state.purge" }

// PurgeMCPStateOrgArgs purges one org's expired MCP state.
type PurgeMCPStateOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (PurgeMCPStateOrgArgs) Kind() string { return "gateway_mcp_state.purge_org" }

// InsertOpts keeps one queued job per org.
func (PurgeMCPStateOrgArgs) InsertOpts() river.InsertOpts { return uniqueQueued }

// fanOut lists orgs through the audited lister (HR-054, purpose "orgs")
// and enqueues one job per org.
func fanOut(ctx context.Context, pool *db.Pool, perOrg func(ids.OrgID) river.JobArgs) error {
	refs, err := pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("gateways housekeeping: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: perOrg(r.Org)})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

type pruneWorker struct {
	river.WorkerDefaults[PruneReplicasArgs]
	pool *db.Pool
}

func (w *pruneWorker) Work(ctx context.Context, _ *river.Job[PruneReplicasArgs]) error {
	return fanOut(ctx, w.pool, func(o ids.OrgID) river.JobArgs { return PruneReplicasOrgArgs{Org: o} })
}

type pruneOrgWorker struct {
	river.WorkerDefaults[PruneReplicasOrgArgs]
	svc *Service
	log *slog.Logger
}

func (w *pruneOrgWorker) Work(ctx context.Context, job *river.Job[PruneReplicasOrgArgs]) error {
	n, err := w.svc.PruneReplicas(ctx, job.Args.Org)
	if n > 0 {
		w.log.InfoContext(ctx, "gateway_replicas.pruned", slog.String("org", job.Args.Org.String()), slog.Int64("replicas", n))
	}
	return err
}

type purgeWorker struct {
	river.WorkerDefaults[PurgeMCPStateArgs]
	pool *db.Pool
}

func (w *purgeWorker) Work(ctx context.Context, _ *river.Job[PurgeMCPStateArgs]) error {
	return fanOut(ctx, w.pool, func(o ids.OrgID) river.JobArgs { return PurgeMCPStateOrgArgs{Org: o} })
}

type purgeOrgWorker struct {
	river.WorkerDefaults[PurgeMCPStateOrgArgs]
	svc *Service
}

func (w *purgeOrgWorker) Work(ctx context.Context, job *river.Job[PurgeMCPStateOrgArgs]) error {
	_, err := w.svc.PurgeMCPState(ctx, job.Args.Org)
	return err
}

// RegisterJobs adds the housekeeping workers to reg.
func (s *Service) RegisterJobs(reg *jobs.Registry, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[PruneReplicasArgs](reg, &pruneWorker{pool: s.pool}); err != nil {
		return err
	}
	if err := jobs.Register[PruneReplicasOrgArgs](reg, &pruneOrgWorker{svc: s, log: log}); err != nil {
		return err
	}
	if err := jobs.Register[PurgeMCPStateArgs](reg, &purgeWorker{pool: s.pool}); err != nil {
		return err
	}
	return jobs.Register[PurgeMCPStateOrgArgs](reg, &purgeOrgWorker{svc: s})
}

// PeriodicJobs returns the housekeeping schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(PruneInterval),
			func() (river.JobArgs, *river.InsertOpts) { return PruneReplicasArgs{}, nil }, nil),
		river.NewPeriodicJob(river.PeriodicInterval(PurgeInterval),
			func() (river.JobArgs, *river.InsertOpts) { return PurgeMCPStateArgs{}, nil }, nil),
	}
}
