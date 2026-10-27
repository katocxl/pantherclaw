// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package support

import (
	"context"
	"log/slog"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

func endedAudit(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, id ids.UUID, reason string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: "breakglass.ended", Actor: actor, Outcome: audit.Success, ReasonCode: reason,
		Object: &audit.Object{Type: "breakglass_activation", ID: id.String()}, Details: map[string]string{"activation": id.String()},
	})
	return err
}

func expireBreakGlass(ctx context.Context, tx db.TenantTx) error {
	ids, err := dbq.New(tx).EndExpiredBreakGlass(ctx, tx.OrgID())
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := endedAudit(ctx, tx, evdomain.Actor{Type: "system", ID: "breakglass_expiry"}, id, "EXPIRED"); err != nil {
			return err
		}
	}
	return nil
}

// ExpireBreakGlass records ended events for expired activations. Expiry
// is enforced at authentication even when the worker is delayed.
func (s *Service) ExpireBreakGlass(ctx context.Context, org ids.OrgID) error {
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error { return expireBreakGlass(ctx, tx) })
}

type breakGlassSweepArgs struct{}

func (breakGlassSweepArgs) Kind() string { return "support.breakglass_sweep" }

type breakGlassSweepWorker struct {
	river.WorkerDefaults[breakGlassSweepArgs]
	s *Service
}

func (w *breakGlassSweepWorker) Work(ctx context.Context, _ *river.Job[breakGlassSweepArgs]) error {
	refs, err := w.s.pool.CrossOrgList(ctx, db.ListAllOrgs, 10000)
	if err != nil {
		return err
	}
	if len(refs) == 10000 {
		w.s.log.WarnContext(ctx, "support.breakglass_sweep_cap", slog.Int("orgs", len(refs)))
	}
	for _, r := range refs {
		if err := w.s.ExpireBreakGlass(ctx, r.Org); err != nil {
			return err
		}
	}
	return nil
}

// Register adds the expiry worker; it also operates on self-hosted nodes
// whose support staff feature is off.
func (s *Service) Register(reg *jobs.Registry) error {
	return jobs.Register[breakGlassSweepArgs](reg, &breakGlassSweepWorker{s: s})
}

// PeriodicJobs schedules auditing of activations that ended by expiry.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(time.Minute), func() (river.JobArgs, *river.InsertOpts) { return breakGlassSweepArgs{}, nil }, nil)}
}
