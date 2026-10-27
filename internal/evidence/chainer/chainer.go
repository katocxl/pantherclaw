// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package chainer runs the evidence chainer as River jobs (ADR-0009).
//
// A periodic dispatch job lists orgs with unchained entries through the
// audited cross-org lister and enqueues one unique chain job per org
// (HR-054). Each chain job works inside that org's tenant transaction.
package chainer

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/evidence/ledger"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

const (
	// Batch is the number of entries linked per transaction.
	Batch = 500
	// DispatchInterval is how often orgs with pending entries are found.
	DispatchInterval   = 2 * time.Second
	maxOrgsPerDispatch = 1000
)

// ChainOrgArgs asks for one org's pending entries to be chained.
type ChainOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (ChainOrgArgs) Kind() string { return "evidence.chain_org" }

// InsertOpts makes chain jobs unique per org while queued or running.
func (ChainOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// ChainOrgWorker chains one org.
type ChainOrgWorker struct {
	river.WorkerDefaults[ChainOrgArgs]
	Pool *db.Pool
	Log  *slog.Logger
}

// Work implements river.Worker.
func (w *ChainOrgWorker) Work(ctx context.Context, job *river.Job[ChainOrgArgs]) error {
	for {
		n, err := ledger.ChainOrg(ctx, w.Pool, job.Args.Org, Batch)
		if err != nil || n < Batch {
			return err
		}
	}
}

// DispatchArgs asks for chain jobs to be enqueued for every org with
// pending entries.
type DispatchArgs struct{}

// Kind implements river.JobArgs.
func (DispatchArgs) Kind() string { return "evidence.chain_dispatch" }

// DispatchWorker lists orgs with pending entries and enqueues chain jobs.
type DispatchWorker struct {
	river.WorkerDefaults[DispatchArgs]
	Pool *db.Pool
}

// Work implements river.Worker.
func (w *DispatchWorker) Work(ctx context.Context, _ *river.Job[DispatchArgs]) error {
	refs, err := w.Pool.CrossOrgList(ctx, db.ListLedgerUnchained, maxOrgsPerDispatch)
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		return nil
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("chainer: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: ChainOrgArgs{Org: r.Org}})
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("chainer: enqueue: %w", err)
	}
	return nil
}

// Register adds the chainer workers to reg.
func Register(reg *jobs.Registry, pool *db.Pool, logs ...*slog.Logger) error {
	log := slog.Default()
	if len(logs) > 0 && logs[0] != nil {
		log = logs[0]
	}
	if err := jobs.Register[ChainOrgArgs](reg, &ChainOrgWorker{Pool: pool, Log: log}); err != nil {
		return err
	}
	if err := jobs.Register[DispatchArgs](reg, &DispatchWorker{Pool: pool}); err != nil {
		return err
	}
	if err := jobs.Register[SecurityOrgArgs](reg, &SecurityOrgWorker{Pool: pool, Log: log}); err != nil {
		return err
	}
	return jobs.Register[SecurityDispatchArgs](reg, &SecurityDispatchWorker{Pool: pool, Log: log})
}

// PeriodicJobs returns the dispatcher schedule for the worker client.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(time.Minute), func() (river.JobArgs, *river.InsertOpts) { return SecurityDispatchArgs{}, nil }, &river.PeriodicJobOpts{RunOnStart: true}),
		river.NewPeriodicJob(
			river.PeriodicInterval(DispatchInterval),
			func() (river.JobArgs, *river.InsertOpts) { return DispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true},
		),
	}
}
