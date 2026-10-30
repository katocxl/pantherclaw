// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// RewrapInterval is how often keystore.rewrap runs. It fans out to the
// platform org (signing keys) and every active org (DEKs); an org whose
// keys are all under the current KEK costs one read.
const RewrapInterval = time.Hour

// RewrapArgs fans the re-wrap out (ids only, HR-056).
type RewrapArgs struct{}

// Kind implements river.JobArgs.
func (RewrapArgs) Kind() string { return "keystore.rewrap" }

// RewrapOrgArgs re-wraps one org's keys.
type RewrapOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (RewrapOrgArgs) Kind() string { return "keystore.rewrap_org" }

// InsertOpts keeps one queued job per org.
func (RewrapOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type rewrapWorker struct {
	river.WorkerDefaults[RewrapArgs]
	pool *db.Pool
}

func (w *rewrapWorker) Work(ctx context.Context, _ *river.Job[RewrapArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("keystore.rewrap: %w", err)
	}
	params := []river.InsertManyParams{{Args: RewrapOrgArgs{Org: ids.PlatformOrg}}}
	for _, r := range refs {
		if r.Org != ids.PlatformOrg {
			params = append(params, river.InsertManyParams{Args: RewrapOrgArgs{Org: r.Org}})
		}
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

type rewrapOrgWorker struct {
	river.WorkerDefaults[RewrapOrgArgs]
	pool *db.Pool // pc_app
	ks   *db.Pool // pc_keystore; nil when not configured
	kp   keys.KeyProvider
	log  *slog.Logger
}

func (w *rewrapOrgWorker) Work(ctx context.Context, job *river.Job[RewrapOrgArgs]) error {
	res, err := RewrapOrg(ctx, w.pool, w.ks, w.kp, job.Args.Org)
	if errors.Is(err, ErrRewrapNotConfigured) {
		w.log.WarnContext(ctx, "keystore.rewrap_unconfigured", slog.String("org", job.Args.Org.String()),
			slog.String("code", "KEY_REWRAP_UNCONFIGURED"))
		return nil
	}
	for _, id := range res.Unroutable {
		// Its keys fail closed at their first unwrap (D170).
		w.log.ErrorContext(ctx, "keys.kek_unroutable", slog.String("org", job.Args.Org.String()), slog.String("kek_id", id))
	}
	if res.DEKs+res.SigningKeys > 0 {
		w.log.InfoContext(ctx, "keystore.rewrapped", slog.String("org", job.Args.Org.String()),
			slog.Int("deks", res.DEKs), slog.Int("signing_keys", res.SigningKeys), slog.String("kek_id", w.kp.CurrentKEK()))
	}
	if err != nil {
		w.log.WarnContext(ctx, "keystore.rewrap_failed", slog.String("org", job.Args.Org.String()), slog.Any("error", err))
	}
	return err
}

// RegisterRewrap adds the re-wrap workers to reg and returns its schedule.
// pool is pc_app's; ks is pc_keystore's, or nil when not configured.
func RegisterRewrap(reg *jobs.Registry, pool, ks *db.Pool, kp keys.KeyProvider, log *slog.Logger) ([]*river.PeriodicJob, error) {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[RewrapArgs](reg, &rewrapWorker{pool: pool}); err != nil {
		return nil, err
	}
	if err := jobs.Register[RewrapOrgArgs](reg, &rewrapOrgWorker{pool: pool, ks: ks, kp: kp, log: log}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(RewrapInterval),
			func() (river.JobArgs, *river.InsertOpts) { return RewrapArgs{}, nil }, nil),
	}, nil
}
