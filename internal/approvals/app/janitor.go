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

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	pgwaitlist "github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

// JanitorInterval is how often the approvals janitor runs.
const JanitorInterval = time.Minute

// Swept counts what one janitor run changed in one org.
type Swept struct {
	Expired, Invalidated, Revalidated int
	// EntriesExpired counts the access requests and tool reviews that
	// passed their deadline (HR-177).
	EntriesExpired int
}

// SweepOrg keeps one org's approval queue honest (decision 6, HR-039,
// HR-170): it expires requests past a deadline, invalidates live requests
// made moot by a change of containment, agent, run, grant chain or
// definition (and restorations whose agent was retired or changed), and
// checks the people of every counting response again
// (voiding responses of removed roles, disabled users and removed or
// suspended keys, and returning approvals no longer met to PENDING).
// Correctness never depends on it: expiry is checked at use, a material
// change gives a new binding, and consumption checks eligibility itself.
// Each request is changed in its own transaction. It also ends the access
// requests and tool reviews past their deadline, which changes nothing.
func SweepOrg(ctx context.Context, pool *db.Pool, n Notifier, org ids.OrgID) (Swept, error) {
	var out Swept
	var overdue []ids.UUID
	var moot []dbq.MootApprovalRequestsRow
	var responded []ids.UUID
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if overdue, err = q.OverdueApprovalRequests(ctx, org); err != nil {
			return err
		}
		if moot, err = q.MootApprovalRequests(ctx, org); err != nil {
			return err
		}
		restorations, err := q.MootRestorations(ctx, org)
		if err != nil {
			return err
		}
		for _, r := range restorations {
			moot = append(moot, dbq.MootApprovalRequestsRow(r))
		}
		responded, err = q.RequestsWithResponses(ctx, org)
		return err
	}, db.ReadOnly())
	if err != nil {
		return out, err
	}
	system := evdomain.Actor{Type: "system", ID: "system"}
	each := func(fn func(context.Context, db.TenantTx) error) error {
		return pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error { return fn(ctx, tx) })
	}
	for _, id := range overdue {
		if err := each(func(ctx context.Context, tx db.TenantTx) error {
			if err := pgapprovals.Expire(ctx, tx, org, id, system); err != nil {
				return err
			}
			return tell(ctx, tx, n, org, id, string(apdomain.StateExpired), "approval.expired", nil)
		}); err != nil {
			return out, err
		}
		out.Expired++
	}
	for _, m := range moot {
		if m.Reason == "" {
			continue
		}
		if err := each(func(ctx context.Context, tx db.TenantTx) error {
			if err := pgapprovals.Invalidate(ctx, tx, org, m.ID, m.Reason); err != nil {
				return err
			}
			return tell(ctx, tx, n, org, m.ID, string(apdomain.StateInvalidated), "approval.invalidated", map[string]string{"reason": m.Reason})
		}); err != nil {
			return out, err
		}
		out.Invalidated++
	}
	for _, id := range responded {
		if err := each(func(ctx context.Context, tx db.TenantTx) error { return pgapprovals.Revalidate(ctx, tx, org, id) }); err != nil {
			return out, err
		}
		out.Revalidated++
	}
	err = each(func(ctx context.Context, tx db.TenantTx) error {
		n, err := pgwaitlist.ExpireEntries(ctx, tx, org)
		out.EntriesExpired = n
		return err
	})
	return out, err
}

// JanitorOrgArgs asks for one org's approvals to be swept. Job args carry
// ids only (HR-056).
type JanitorOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (JanitorOrgArgs) Kind() string { return "approvals.janitor_org" }

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
	pool   *db.Pool
	notify Notifier
	log    *slog.Logger
}

func (w *janitorOrgWorker) Work(ctx context.Context, job *river.Job[JanitorOrgArgs]) error {
	s, err := SweepOrg(ctx, w.pool, w.notify, job.Args.Org)
	if s.Expired+s.Invalidated+s.EntriesExpired > 0 {
		w.log.InfoContext(ctx, "approvals.janitor", slog.String("org", job.Args.Org.String()),
			slog.Int("expired", s.Expired), slog.Int("invalidated", s.Invalidated), slog.Int("entries_expired", s.EntriesExpired))
	}
	return err
}

// JanitorDispatchArgs fans the janitor out to every active org.
type JanitorDispatchArgs struct{}

// Kind implements river.JobArgs.
func (JanitorDispatchArgs) Kind() string { return "approvals.janitor_dispatch" }

type janitorDispatchWorker struct {
	river.WorkerDefaults[JanitorDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *janitorDispatchWorker) Work(ctx context.Context, _ *river.Job[JanitorDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("approvals janitor: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: JanitorOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJanitor adds the janitor workers to reg.
func RegisterJanitor(reg *jobs.Registry, pool *db.Pool, n Notifier, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[JanitorOrgArgs](reg, &janitorOrgWorker{pool: pool, notify: n, log: log}); err != nil {
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
