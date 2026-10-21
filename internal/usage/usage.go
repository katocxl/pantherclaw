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
// created during the day; and stored bytes as a running total (D45): the
// previous day's, plus the stored byte columns of the ledger entries,
// decision receipts, payload captures and evidence packs created that day,
// minus the ledger bytes the retention remover took out that day. Each
// hourly run reads only that day's rows; the weekly recount
// (usage.recount_weekly, Sunday 03:00 UTC, one org at a time) re-baselines
// from a full sum so drift never accumulates.
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

// Recount re-baselines org's stored bytes (D45): the day before yesterday
// gets a full sum of the stored byte columns (plus what the remover took
// out since), then yesterday and today are recomputed on top of it, so the
// running totals end at the true total. Each step runs within the
// database's statement timeout.
func (s *Service) Recount(ctx context.Context, org ids.OrgID) error {
	now := s.clock.Now().UTC()
	base := pgDate(now.AddDate(0, 0, -2))
	if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.MeterUsageDay(ctx, org, base, 0); err != nil {
			return err
		}
		_, err := q.RebaselineStoredBytes(ctx, org, base)
		return err
	}); err != nil {
		return err
	}
	return s.Meter(ctx, org)
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

// ListerCap is how many active orgs one fan-out lists; more are skipped
// with a warning (paging the lister is a shared follow-up, D45).
const ListerCap = 10000

// activeOrgs lists the active orgs through the audited lister (HR-054),
// warning when the cap cuts the list short.
func activeOrgs(ctx context.Context, pool *db.Pool, log *slog.Logger, job string) ([]ids.OrgID, error) {
	refs, err := pool.CrossOrgList(ctx, db.ListActiveOrgs, ListerCap)
	if err != nil {
		return nil, err
	}
	if len(refs) >= ListerCap {
		log.WarnContext(ctx, "usage.lister_cap_reached", slog.String("job", job), slog.Int("cap", ListerCap),
			slog.String("note", "orgs past the cap are not metered in this run"))
	}
	out := make([]ids.OrgID, len(refs))
	for i, r := range refs {
		out[i] = r.Org
	}
	return out, nil
}

type meterDailyWorker struct {
	river.WorkerDefaults[MeterDailyArgs]
	pool *db.Pool
	log  *slog.Logger
}

// Work enqueues one meter job per active org.
func (w *meterDailyWorker) Work(ctx context.Context, _ *river.Job[MeterDailyArgs]) error {
	orgs, err := activeOrgs(ctx, w.pool, w.log, MeterDailyArgs{}.Kind())
	if err != nil || len(orgs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("usage meters: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(orgs))
	for _, org := range orgs {
		params = append(params, river.InsertManyParams{Args: MeterOrgArgs{Org: org}})
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

// RecountWeeklyArgs re-baselines every active org's stored bytes, one org
// at a time (D45).
type RecountWeeklyArgs struct{}

// Kind implements river.JobArgs.
func (RecountWeeklyArgs) Kind() string { return "usage.recount_weekly" }

// RecountTimeout bounds one weekly recount run; each org's statements stay
// within the database's statement timeout.
const RecountTimeout = 6 * time.Hour

type recountWorker struct {
	river.WorkerDefaults[RecountWeeklyArgs]
	svc *Service
	log *slog.Logger
}

// Timeout lets the run go through every org.
func (*recountWorker) Timeout(*river.Job[RecountWeeklyArgs]) time.Duration { return RecountTimeout }

// Work recounts each org in turn; an org whose recount fails (for example
// past the statement timeout) is logged and skipped.
func (w *recountWorker) Work(ctx context.Context, _ *river.Job[RecountWeeklyArgs]) error {
	orgs, err := activeOrgs(ctx, w.svc.pool, w.log, RecountWeeklyArgs{}.Kind())
	if err != nil {
		return err
	}
	skipped := 0
	for _, org := range orgs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.svc.Recount(ctx, org); err != nil {
			skipped++
			w.log.WarnContext(ctx, "usage.recount_skipped", slog.String("org", org.String()), pclog.Err(err))
		}
	}
	w.log.InfoContext(ctx, "usage.recount_done", slog.Int("orgs", len(orgs)), slog.Int("skipped", skipped))
	return nil
}

// Register adds the meter workers to reg.
func Register(reg *jobs.Registry, svc *Service, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[MeterDailyArgs](reg, &meterDailyWorker{pool: svc.pool, log: log}); err != nil {
		return err
	}
	if err := jobs.Register[RecountWeeklyArgs](reg, &recountWorker{svc: svc, log: log}); err != nil {
		return err
	}
	return jobs.Register[MeterOrgArgs](reg, &meterOrgWorker{svc: svc, log: log})
}

// weeklyOffPeak is Sunday 03:00 UTC, every week.
type weeklyOffPeak struct{}

// Next implements river.PeriodicSchedule.
func (weeklyOffPeak) Next(current time.Time) time.Time {
	t := current.UTC()
	next := time.Date(t.Year(), t.Month(), t.Day(), 3, 0, 0, 0, time.UTC).AddDate(0, 0, (7-int(t.Weekday()))%7)
	if !next.After(t) {
		next = next.AddDate(0, 0, 7)
	}
	return next
}

// PeriodicJobs returns the meters' hourly schedule and the weekly recount
// (Sunday 03:00 UTC).
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(MeterInterval),
			func() (river.JobArgs, *river.InsertOpts) { return MeterDailyArgs{}, nil }, nil),
		river.NewPeriodicJob(weeklyOffPeak{},
			func() (river.JobArgs, *river.InsertOpts) { return RecountWeeklyArgs{}, nil }, nil),
	}
}
