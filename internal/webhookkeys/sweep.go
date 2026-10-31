// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhookkeys

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// The expired-key sweep (D271, HR-512): every hour, per org, a RETIRING
// webhooks key whose 24-hour overlap has ended moves to REVOKED, audited
// `overlap_ended`. The JWKS and signing never depend on it: they already
// leave such a key out.

// SweepInterval is how often the sweep runs.
const SweepInterval = time.Hour

// SweepOrgArgs asks for one org's expired webhook keys to be revoked (ids
// only, HR-056).
type SweepOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SweepOrgArgs) Kind() string { return "webhookkeys.expired_sweep_org" }

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
	keys *keystore.WebhookKeys
	log  *slog.Logger
}

func (w *sweepOrgWorker) Work(ctx context.Context, job *river.Job[SweepOrgArgs]) error {
	n, err := w.keys.RevokeExpiredWebhookKeys(ctx, job.Args.Org)
	if n > 0 {
		w.log.InfoContext(ctx, "webhookkeys.expired_revoked", slog.String("org", job.Args.Org.String()), slog.Int("keys", n))
	}
	return err
}

// SweepDispatchArgs fans the sweep out to every active org.
type SweepDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SweepDispatchArgs) Kind() string { return "webhookkeys.expired_sweep_dispatch" }

type sweepDispatchWorker struct {
	river.WorkerDefaults[SweepDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054, purpose "orgs") and
// enqueues one job per org.
func (w *sweepDispatchWorker) Work(ctx context.Context, _ *river.Job[SweepDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("webhookkeys sweep: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		if r.Org == ids.PlatformOrg {
			continue
		}
		params = append(params, river.InsertManyParams{Args: SweepOrgArgs{Org: r.Org}})
	}
	if len(params) == 0 {
		return nil
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJobs adds the sweep workers to reg.
func RegisterJobs(reg *jobs.Registry, pool *db.Pool, keys *keystore.WebhookKeys, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[SweepOrgArgs](reg, &sweepOrgWorker{keys: keys, log: log}); err != nil {
		return err
	}
	return jobs.Register[SweepDispatchArgs](reg, &sweepDispatchWorker{pool: pool})
}

// PeriodicJobs returns the sweep schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepDispatchArgs{}, nil }, nil),
	}
}
