// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	podomain "github.com/katocxl/pantherclaw/internal/posture/domain"
)

// GenerateArgs asks for one finding's suggestion to be created, refreshed
// or made stale (D91). Job args carry ids only (HR-056): the finding as
// its canonical UUID string.
type GenerateArgs struct {
	Org     ids.OrgID `json:"org"`
	Finding string    `json:"finding"`
}

// Kind implements river.JobArgs.
func (GenerateArgs) Kind() string { return "suggestions.generate" }

// InsertOpts keeps one waiting job per finding: every recomputation sees
// the finding again (at least hourly), so one generation in flight is
// enough.
func (GenerateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// Queue enqueues the generation of an unused-authority finding's
// suggestion in the recomputation's own transaction (D91): it implements
// the posture reconciliation's FindingHook.
type Queue struct {
	// Jobs nil is the client of the job the recomputation runs in.
	Jobs *jobs.Client
}

// FindingChanged implements poapp.FindingHook.
func (q *Queue) FindingChanged(ctx context.Context, tx db.TenantTx, finding ids.UUID, kind podomain.Kind) error {
	if kind != podomain.UnusedAuthority {
		return nil
	}
	c := q.Jobs
	if c == nil {
		var err error
		if c, err = river.ClientFromContextSafely[jobs.TxType](ctx); err != nil {
			return fmt.Errorf("suggestions: %w", err)
		}
	}
	return jobs.InsertTx(ctx, c, tx, GenerateArgs{Org: tx.OrgID(), Finding: finding.String()}, nil)
}

type generateWorker struct {
	river.WorkerDefaults[GenerateArgs]
	pool *db.Pool
	log  *slog.Logger
}

// Work generates in the finding's org.
func (w *generateWorker) Work(ctx context.Context, job *river.Job[GenerateArgs]) error {
	finding, err := ids.ParseUUID(job.Args.Finding)
	if err != nil {
		return river.JobCancel(fmt.Errorf("suggestions: finding %q: %w", job.Args.Finding, err))
	}
	var out Outcome
	err = w.pool.InTenantTx(ctx, job.Args.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = Generate(ctx, tx, finding)
		return err
	})
	if err == nil && out != Skipped {
		w.log.InfoContext(ctx, "suggestions.generated", slog.String("org", job.Args.Org.String()),
			slog.String("finding", job.Args.Finding), slog.String("outcome", string(out)))
	}
	return err
}

// Register adds the generation worker to reg.
func Register(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	return jobs.Register[GenerateArgs](reg, &generateWorker{pool: pool, log: log})
}
