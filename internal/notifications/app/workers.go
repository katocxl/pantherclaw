// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// JanitorInterval is how often old notifications and deliveries are removed.
const JanitorInterval = 30 * time.Minute

type deliverWorker struct {
	river.WorkerDefaults[DeliverArgs]
	svc *Service
}

// Work makes one attempt. A destination's Retry-After snoozes the job; any
// other failure is retried on the delivery schedule (domain.RetryDelay).
func (w *deliverWorker) Work(ctx context.Context, job *river.Job[DeliverArgs]) error {
	err := w.svc.Deliver(ctx, job.Args.Org, job.Args.Delivery.UUID())
	var wait RetryAfterError
	if errors.As(err, &wait) {
		return river.JobSnooze(wait.Wait)
	}
	return err
}

// NextRetry follows the delivery schedule (domain.RetryDelay, HR-159).
func (w *deliverWorker) NextRetry(job *river.Job[DeliverArgs]) time.Time {
	return time.Now().Add(domain.RetryDelay(job.Attempt))
}

// Timeout bounds one attempt: the request plus decryption and bookkeeping.
func (w *deliverWorker) Timeout(*river.Job[DeliverArgs]) time.Duration {
	return RequestTimeout + 20*time.Second
}

// JanitorOrgArgs asks for one org's notifications to be cleaned (ids only,
// HR-056).
type JanitorOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (JanitorOrgArgs) Kind() string { return "notifications.janitor_org" }

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

// Cleaned counts what one janitor run did.
type Cleaned struct {
	Expired, Deliveries, Notifications int64
}

// CleanOrg expires pending deliveries of long-expired notifications, then
// removes deliveries finished more than 30 days ago and the notifications
// left without any.
func CleanOrg(ctx context.Context, pool *db.Pool, org ids.OrgID) (Cleaned, error) {
	var c Cleaned
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if c.Expired, err = q.ExpireStaleDeliveries(ctx, org); err != nil {
			return err
		}
		if c.Deliveries, err = q.DeleteOldDeliveries(ctx, org); err != nil {
			return err
		}
		c.Notifications, err = q.DeleteOldNotifications(ctx, org)
		return err
	})
	return c, err
}

type janitorOrgWorker struct {
	river.WorkerDefaults[JanitorOrgArgs]
	pool *db.Pool
	log  *slog.Logger
}

func (w *janitorOrgWorker) Work(ctx context.Context, job *river.Job[JanitorOrgArgs]) error {
	c, err := CleanOrg(ctx, w.pool, job.Args.Org)
	if err == nil && c.Expired+c.Deliveries+c.Notifications > 0 {
		w.log.InfoContext(ctx, "notifications.janitor", slog.String("org", job.Args.Org.String()), slog.Int64("expired", c.Expired),
			slog.Int64("deliveries", c.Deliveries), slog.Int64("notifications", c.Notifications))
	}
	return err
}

// JanitorDispatchArgs fans the janitor out to every active org.
type JanitorDispatchArgs struct{}

// Kind implements river.JobArgs.
func (JanitorDispatchArgs) Kind() string { return "notifications.janitor_dispatch" }

type janitorDispatchWorker struct {
	river.WorkerDefaults[JanitorDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *janitorDispatchWorker) Work(ctx context.Context, _ *river.Job[JanitorDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("notifications janitor: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: JanitorOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterWorkers adds the delivery worker and the janitor to reg.
func RegisterWorkers(reg *jobs.Registry, svc *Service) error {
	if err := jobs.Register[DeliverArgs](reg, &deliverWorker{svc: svc}); err != nil {
		return err
	}
	if err := jobs.Register[JanitorOrgArgs](reg, &janitorOrgWorker{pool: svc.pool, log: svc.log}); err != nil {
		return err
	}
	if err := registerSlackReconciler(reg, svc); err != nil {
		return err
	}
	return jobs.Register[JanitorDispatchArgs](reg, &janitorDispatchWorker{pool: svc.pool})
}

// PeriodicJobs schedules the janitor.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(JanitorInterval),
			func() (river.JobArgs, *river.InsertOpts) { return JanitorDispatchArgs{}, nil }, nil),
		slackReconcilePeriodic(),
	}
}
