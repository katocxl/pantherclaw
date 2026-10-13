// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"context"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// Jobs. CreateEvidencePack enqueues one build job in its own transaction
// (ids only, HR-056). An hourly job expires ready packs past their 7 days:
// it lists the active orgs through the audited cross-org lister with the
// existing purpose "orgs" (no purpose of its own: the lister's one
// redefinition in this batch belongs to the retention slice) and works in
// each org's tenant transaction.
const (
	buildTimeout     = 9 * time.Minute
	buildAttempts    = 3
	ExpiryInterval   = time.Hour
	maxOrgsPerExpiry = 10_000
)

// Pack is the kind of an evidence pack's id in job arguments.
type Pack struct{}

// KindName implements ids.Kind.
func (Pack) KindName() string { return "evidence pack" }

// BuildArgs asks for one pack's build.
type BuildArgs struct {
	Org  ids.OrgID    `json:"org"`
	Pack ids.ID[Pack] `json:"pack"`
}

// NewBuildArgs returns the build job of pack (a UUIDv7) of org.
func NewBuildArgs(org ids.OrgID, pack ids.UUID) (BuildArgs, error) {
	id, err := ids.FromUUID[Pack](pack)
	return BuildArgs{Org: org, Pack: id}, err
}

// Kind implements river.JobArgs.
func (BuildArgs) Kind() string { return "evidence.pack_build" }

// InsertOpts makes a build unique per pack while queued or running, with a
// few attempts.
func (BuildArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: buildAttempts, UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// ExpireArgs asks for the expiry of ready packs past their 7 days.
type ExpireArgs struct{}

// Kind implements river.JobArgs.
func (ExpireArgs) Kind() string { return "evidence.pack_expire" }

type buildWorker struct {
	river.WorkerDefaults[BuildArgs]
	svc *Service
}

func (w *buildWorker) Timeout(*river.Job[BuildArgs]) time.Duration { return buildTimeout }

// Work builds the pack; the last failed attempt marks it FAILED.
func (w *buildWorker) Work(ctx context.Context, job *river.Job[BuildArgs]) error {
	err := w.svc.Build(ctx, job.Args.Org, job.Args.Pack.UUID())
	if err != nil && job.Attempt >= job.MaxAttempts {
		w.svc.log().ErrorContext(ctx, "evidence.pack_build_failed", slog.String("pack", job.Args.Pack.UUID().String()), slog.String("error", err.Error()))
		return w.svc.fail(ctx, job.Args.Org, job.Args.Pack.UUID(), CodeBuildFailed)
	}
	return err
}

type expireWorker struct {
	river.WorkerDefaults[ExpireArgs]
	svc *Service
}

func (w *expireWorker) Work(ctx context.Context, _ *river.Job[ExpireArgs]) error {
	refs, err := w.svc.Pool.CrossOrgList(ctx, db.ListActiveOrgs, maxOrgsPerExpiry)
	if err != nil {
		return err
	}
	for _, r := range refs {
		if err := w.svc.Expire(ctx, r.Org); err != nil {
			return err
		}
	}
	return nil
}

// Expire expires org's ready packs past their 7 days: their content goes.
func (s *Service) Expire(ctx context.Context, org ids.OrgID) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).ExpireEvidencePacks(ctx, org)
		return err
	})
}

// Register adds the pack workers to reg.
func Register(reg *jobs.Registry, svc *Service) error {
	if err := jobs.Register[BuildArgs](reg, &buildWorker{svc: svc}); err != nil {
		return err
	}
	return jobs.Register[ExpireArgs](reg, &expireWorker{svc: svc})
}

// PeriodicJobs returns the expiry's schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(ExpiryInterval),
			func() (river.JobArgs, *river.InsertOpts) { return ExpireArgs{}, nil }, nil),
	}
}
