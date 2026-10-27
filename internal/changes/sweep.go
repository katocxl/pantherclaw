// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package changes

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// The expiry sweep (D91 K7): every minute, per org, pending requests past
// their expiry become EXPIRED, with change.expired and the kind's Closed
// callback, so a domain learns of the expiry without anyone touching the
// org's requests.

// SweepInterval is how often the expiry sweep runs.
const SweepInterval = time.Minute

// systemActor is PantherClaw expiring requests by itself.
var systemActor = evdomain.Actor{Type: "system", ID: "changes"}

// ExpireOrg expires one org's overdue pending requests and returns how many.
func (s *Service) ExpireOrg(ctx context.Context, org ids.OrgID) (int, error) {
	n := 0
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		before, err := q.CountOverdueChangeRequests(ctx, org)
		if err != nil || before == 0 {
			return err
		}
		n = int(before)
		return s.expire(ctx, tx, q, systemActor)
	})
	return n, err
}

// ExpireOrgArgs asks for one org's requests to be expired (ids only, HR-056).
type ExpireOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (ExpireOrgArgs) Kind() string { return "changes.expire_org" }

// InsertOpts keeps one queued job per org.
func (ExpireOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type expireOrgWorker struct {
	river.WorkerDefaults[ExpireOrgArgs]
	svc *Service
	log *slog.Logger
}

func (w *expireOrgWorker) Work(ctx context.Context, job *river.Job[ExpireOrgArgs]) error {
	n, err := w.svc.ExpireOrg(ctx, job.Args.Org)
	if n > 0 {
		w.log.InfoContext(ctx, "changes.expired", slog.String("org", job.Args.Org.String()), slog.Int("requests", n))
	}
	return err
}

// ExpireDispatchArgs fans the expiry sweep out to every active org.
type ExpireDispatchArgs struct{}

// Kind implements river.JobArgs.
func (ExpireDispatchArgs) Kind() string { return "changes.expire_dispatch" }

type expireDispatchWorker struct {
	river.WorkerDefaults[ExpireDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054, purpose "orgs") and
// enqueues one job per org.
func (w *expireDispatchWorker) Work(ctx context.Context, _ *river.Job[ExpireDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("changes expiry: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: ExpireOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJobs adds the expiry sweep's workers to reg.
func (s *Service) RegisterJobs(reg *jobs.Registry, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[ExpireOrgArgs](reg, &expireOrgWorker{svc: s, log: log}); err != nil {
		return err
	}
	return jobs.Register[ExpireDispatchArgs](reg, &expireDispatchWorker{pool: s.Pool})
}

// PeriodicJobs returns the expiry sweep's schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return ExpireDispatchArgs{}, nil }, nil),
	}
}
