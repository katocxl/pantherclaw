// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package usage meters what each organization uses, per UTC day (G0 M13
// D10, D11; F6; HR-377): agents, the peak of admitted instances, runs
// started and an approximation of stored data. The numbers are computed by
// the server's job usage.meter_daily from the org's own records — never
// reported by a client — and read through UsageService.ListUsage. Nothing
// enforces them yet: limits.usage.enforce refuses true.
//
// The method (migration 00171): agents that existed during the day and
// were not retired before it (range agents excluded); the highest number
// of ADMITTED instances the hourly job sampled during the day; runs
// created during the day; and the stored byte columns of the org's ledger
// entries, decision receipts, payload captures and evidence packs created
// before the day ended.
package usage

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// MaxDays bounds ListUsage.
const MaxDays = 90

// Day is one UTC day of an org's usage.
type Day struct {
	Day           time.Time // midnight UTC
	Agents        int
	InstancesPeak int
	Runs          int
	StoredBytes   int64
}

// ErrDays refuses a ListUsage outside 1..MaxDays.
var ErrDays = pcerr.New(pcerr.InvalidArgument, "INVALID_DAYS", "days must be 1 to 90")

// Service meters and reads usage.
type Service struct {
	pool  *db.Pool
	clock clock.Clock
}

// New returns the usage service on clk (the system clock when nil).
func New(pool *db.Pool, clk clock.Clock) *Service {
	if clk == nil {
		clk = clock.System{}
	}
	return &Service{pool: pool, clock: clk}
}

func pgDate(t time.Time) pgtype.Date {
	y, m, d := t.UTC().Date()
	return pgtype.Date{Time: time.Date(y, m, d, 0, 0, 0, 0, time.UTC), Valid: true}
}

// List returns the caller's org's last days days (today included), newest
// first; days without a row are left out (entitlements.read).
func (s *Service) List(ctx context.Context, days int) ([]Day, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if !c.CanAnywhere(td.PermEntitlementsRead) {
		return nil, td.ErrPermissionDenied(td.PermEntitlementsRead)
	}
	if days < 1 || days > MaxDays {
		return nil, ErrDays
	}
	since := s.clock.Now().UTC().AddDate(0, 0, -(days - 1))
	var out []Day
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListUsageDays(ctx, c.Org, pgDate(since))
		if err != nil {
			return err
		}
		out = make([]Day, 0, len(rows))
		for _, r := range rows {
			out = append(out, Day{
				Day: r.Day.Time, Agents: int(r.Agents), InstancesPeak: int(r.InstancesPeak), Runs: int(r.Runs), StoredBytes: r.StoredBytes,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Meter recomputes org's today and yesterday (UTC): today with a new
// instances sample, yesterday keeping its recorded peak.
func (s *Service) Meter(ctx context.Context, org ids.OrgID) error {
	now := s.clock.Now().UTC()
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sample, err := q.CountAdmittedInstances(ctx, org)
		if err != nil {
			return err
		}
		if err := q.MeterUsageDay(ctx, org, pgDate(now.AddDate(0, 0, -1)), 0); err != nil {
			return err
		}
		return q.MeterUsageDay(ctx, org, pgDate(now), sample)
	})
}

// MeterInterval is how often usage is recomputed.
const MeterInterval = time.Hour

// MeterDailyArgs fans the meters out to every active org, hourly.
type MeterDailyArgs struct{}

// Kind implements river.JobArgs.
func (MeterDailyArgs) Kind() string { return "usage.meter_daily" }

// MeterOrgArgs recomputes one org. Job args carry ids only (HR-056).
type MeterOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (MeterOrgArgs) Kind() string { return "usage.meter_org" }

// InsertOpts keeps one queued job per org.
func (MeterOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type meterDailyWorker struct {
	river.WorkerDefaults[MeterDailyArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one
// job per org.
func (w *meterDailyWorker) Work(ctx context.Context, _ *river.Job[MeterDailyArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("usage meters: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: MeterOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

type meterOrgWorker struct {
	river.WorkerDefaults[MeterOrgArgs]
	svc *Service
	log *slog.Logger
}

func (w *meterOrgWorker) Work(ctx context.Context, job *river.Job[MeterOrgArgs]) error {
	if err := w.svc.Meter(ctx, job.Args.Org); err != nil {
		w.log.ErrorContext(ctx, "usage.meter_failed", slog.String("org", job.Args.Org.String()), pclog.Err(err))
		return err
	}
	return nil
}

// Register adds the meter workers to reg.
func Register(reg *jobs.Registry, svc *Service, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[MeterDailyArgs](reg, &meterDailyWorker{pool: svc.pool}); err != nil {
		return err
	}
	return jobs.Register[MeterOrgArgs](reg, &meterOrgWorker{svc: svc, log: log})
}

// PeriodicJobs returns the meters' hourly schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(MeterInterval),
			func() (river.JobArgs, *river.InsertOpts) { return MeterDailyArgs{}, nil }, nil),
	}
}
