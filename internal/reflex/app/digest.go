// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// DigestInterval is how often the digest looks for a finished day.
const DigestInterval = time.Hour

// Digests sends each org's daily digest (Team, F620): decisions, authority
// changes and new alerts of the previous UTC day, through notifications,
// with its delivery state tracked in pc.reflex_digests.
type Digests struct {
	Pool   *db.Pool
	Notify Notifier
	Ents   Entitlements
	// Sink records the lapse failure (optional).
	Sink *failures.Sink
	Now  func() time.Time
}

// DigestEnqueued is a digest whose notification is queued; delivery state
// is then the notification's own (D59 L8).
const DigestEnqueued = "ENQUEUED"

// Send records and sends org's digest for the previous UTC day, once. It
// reports whether it sent one. Without Team it does nothing.
func (d *Digests) Send(ctx context.Context, org ids.OrgID) (bool, error) {
	ctx = tenantctx.WithOrg(ctx, org) // the org's entitlements (G0 UI D9)
	if d.Ents == nil || d.Notify == nil {
		return false, nil
	}
	e, err := d.Ents.Current(ctx)
	if err != nil {
		return false, err
	}
	if !e.ReflexTeam() {
		return false, d.lapsed(ctx, org, e)
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	day := now().UTC().Truncate(24 * time.Hour).Add(-24 * time.Hour)
	date := pgtype.Date{Time: day, Valid: true}
	sent := false
	err = d.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.InsertDigest(ctx, org, date)
		if db.IsNoRows(err) {
			return nil // already recorded
		} else if err != nil {
			return err
		}
		// A failed enqueue rolls the digest row back too, so the next run
		// retries it (D59 L8).
		if _, err := d.Notify.Enqueue(ctx, tx, napp.Message{
			Org: org, Type: reflexdomain.NotifyDigest, DedupeKey: reflexdomain.NotifyDigest + ":" + day.Format(time.DateOnly),
			Params: map[string]string{
				"day": day.Format(time.DateOnly), "decisions": strconv.Itoa(int(row.Decisions)),
				"authority_changes": strconv.Itoa(int(row.AuthorityChanges)), "alerts": strconv.Itoa(int(row.Alerts)),
			},
		}); err != nil {
			return err
		}
		sent = true
		return q.MarkDigest(ctx, DigestEnqueued, org, date)
	})
	return sent, err
}

// DigestOrgArgs asks for one org's digest. Job args carry ids only.
type DigestOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (DigestOrgArgs) Kind() string { return "reflex.digest_org" }

// InsertOpts keeps one queued job per org.
func (DigestOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type digestOrgWorker struct {
	river.WorkerDefaults[DigestOrgArgs]
	d *Digests
}

func (w *digestOrgWorker) Work(ctx context.Context, job *river.Job[DigestOrgArgs]) error {
	_, err := w.d.Send(ctx, job.Args.Org)
	return err
}

// DigestDispatchArgs fans the digest out to every active org.
type DigestDispatchArgs struct{}

// Kind implements river.JobArgs.
func (DigestDispatchArgs) Kind() string { return "reflex.digest_dispatch" }

type digestDispatchWorker struct {
	river.WorkerDefaults[DigestDispatchArgs]
	pool *db.Pool
}

func (w *digestDispatchWorker) Work(ctx context.Context, _ *river.Job[DigestDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("reflex digest: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: DigestOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterDigest adds the digest's workers to reg and returns its schedule.
func RegisterDigest(reg *jobs.Registry, d *Digests) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[DigestOrgArgs](reg, &digestOrgWorker{d: d}); err != nil {
		return nil, err
	}
	if err := jobs.Register[DigestDispatchArgs](reg, &digestDispatchWorker{pool: d.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(DigestInterval),
			func() (river.JobArgs, *river.InsertOpts) { return DigestDispatchArgs{}, nil }, nil),
	}, nil
}

// lapsed records, once while it stays open, that a lapsed licence stopped
// the daily digest (D5, D59 L6). Community without a licence sends nothing
// and records nothing.
func (d *Digests) lapsed(ctx context.Context, org ids.OrgID, e billing.Entitlements) error {
	if e.Status != billing.StatusExpired || d.Sink == nil {
		return nil
	}
	return d.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, _, err := d.Sink.ReportTx(ctx, tx, reflexdomain.Failure{
			Org: org, Kind: "reflex.digest_lapsed", DedupeKey: "reflex.digest_lapsed",
			Summary:  "The licence expired, so the daily digest stopped.",
			NextStep: "Renew the licence to receive it again.",
		})
		return err
	})
}
