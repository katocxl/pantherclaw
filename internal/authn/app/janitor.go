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

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// JanitorInterval is how often expired authentication rows are removed.
const JanitorInterval = 10 * time.Minute

// Cleaned counts the rows one janitor run removed.
type Cleaned struct {
	Replay, DeviceCodes, Sessions int64
	// Browser sign-in (M5): pending sign-ins, WebAuthn ceremonies and
	// browser sessions.
	LoginRequests, Ceremonies, BrowserSessions int64
}

// CleanOrg removes one org's expired client-assertion jtis (an expired
// assertion can no longer be replayed), device codes closed for a day and
// CLI sessions that ended more than 30 days ago, and the same for browser
// sign-ins, WebAuthn ceremonies and browser sessions.
func CleanOrg(ctx context.Context, pool *db.Pool, org ids.OrgID) (Cleaned, error) {
	var c Cleaned
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if c.Replay, err = q.DeleteExpiredReplay(ctx, org); err != nil {
			return err
		}
		if c.DeviceCodes, err = q.DeleteOldDeviceCodes(ctx, org); err != nil {
			return err
		}
		if c.Sessions, err = q.DeleteOldSessions(ctx, org); err != nil {
			return err
		}
		return cleanBrowser(ctx, q, org, &c)
	})
	return c, err
}

// JanitorOrgArgs asks for one org to be cleaned. Job args carry ids only
// (HR-056).
type JanitorOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (JanitorOrgArgs) Kind() string { return "authn.janitor_org" }

// InsertOpts keeps one queued job per org.
func (JanitorOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type janitorOrgWorker struct {
	river.WorkerDefaults[JanitorOrgArgs]
	pool *db.Pool
	log  *slog.Logger
}

func (w *janitorOrgWorker) Work(ctx context.Context, job *river.Job[JanitorOrgArgs]) error {
	c, err := CleanOrg(ctx, w.pool, job.Args.Org)
	if err == nil && c.Replay+c.DeviceCodes+c.Sessions+c.LoginRequests+c.Ceremonies+c.BrowserSessions > 0 {
		w.log.InfoContext(ctx, "authn.janitor", slog.String("org", job.Args.Org.String()), slog.Int64("replay", c.Replay),
			slog.Int64("device_codes", c.DeviceCodes), slog.Int64("sessions", c.Sessions),
			slog.Int64("login_requests", c.LoginRequests), slog.Int64("ceremonies", c.Ceremonies),
			slog.Int64("browser_sessions", c.BrowserSessions))
	}
	return err
}

// JanitorDispatchArgs fans the janitor out to every active org.
type JanitorDispatchArgs struct{}

// Kind implements river.JobArgs.
func (JanitorDispatchArgs) Kind() string { return "authn.janitor_dispatch" }

type janitorDispatchWorker struct {
	river.WorkerDefaults[JanitorDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *janitorDispatchWorker) Work(ctx context.Context, _ *river.Job[JanitorDispatchArgs]) error {
	if err := CleanAccounts(ctx, w.pool); err != nil {
		return err
	}
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("authn janitor: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: JanitorOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJanitor adds the janitor workers to reg.
func RegisterJanitor(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[JanitorOrgArgs](reg, &janitorOrgWorker{pool: pool, log: log}); err != nil {
		return err
	}
	return jobs.Register[JanitorDispatchArgs](reg, &janitorDispatchWorker{pool: pool})
}

// JanitorPeriodicJobs returns the janitor schedule.
func JanitorPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(JanitorInterval),
			func() (river.JobArgs, *river.InsertOpts) { return JanitorDispatchArgs{}, nil }, nil),
	}
}

// cleanBrowser removes expired browser sign-ins and ceremonies, then browser
// sessions that ended or expired more than 30 days ago (ceremonies first:
// they reference sessions).
func cleanBrowser(ctx context.Context, q *dbq.Queries, org ids.OrgID, c *Cleaned) error {
	var err error
	if c.LoginRequests, err = q.DeleteOldLoginRequests(ctx, org); err != nil {
		return err
	}
	if c.Ceremonies, err = q.DeleteOldWebAuthnCeremonies(ctx, org); err != nil {
		return err
	}
	c.BrowserSessions, err = q.DeleteOldBrowserSessions(ctx, org)
	return err
}

// CleanAccounts removes sign-ins without an org that expired a day ago and
// account sessions that ended or expired 30 days ago (G0 UI D8), in the
// accounts purpose.
func CleanAccounts(ctx context.Context, pool *db.Pool) error {
	return pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		if _, err := q.DeleteOldAccountLoginRequests(ctx); err != nil {
			return err
		}
		_, err := q.DeleteOldAccountSessions(ctx)
		return err
	})
}
