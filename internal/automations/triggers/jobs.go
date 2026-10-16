// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// Background work per org (D17–D23): each task has a periodic dispatcher
// that lists active orgs through the audited lister and enqueues one
// unique job per org and task. Job args carry ids and names only (HR-056).
const (
	TaskFeed       = "feed"
	TaskSchedules  = "schedules"
	TaskConditions = "conditions"
	TaskDeliveries = "deliveries"
	TaskJanitor    = "janitor"
	// DeliveryInterval is how often due deliveries are sent.
	DeliveryInterval = 15 * time.Second
	// JanitorInterval is how often expired claims, receipts and queued
	// triggers are cleaned up.
	JanitorInterval = 10 * time.Minute
)

var intervals = map[string]time.Duration{
	TaskFeed: FeedInterval, TaskSchedules: ScheduleInterval, TaskConditions: ConditionInterval,
	TaskDeliveries: DeliveryInterval, TaskJanitor: JanitorInterval,
}

// Endpoints is the endpoints' share of the background work (sending due
// deliveries, pruning receipts); nil leaves it out.
type Endpoints interface {
	SendDue(ctx context.Context, org ids.OrgID) (int, error)
	PruneReceipts(ctx context.Context, org ids.OrgID) (int64, error)
}

// OrgArgs asks for one task of one org.
type OrgArgs struct {
	Org  ids.OrgID `json:"org"`
	Task string    `json:"task"`
}

// Kind implements river.JobArgs.
func (OrgArgs) Kind() string { return "automations.triggers_org" }

// InsertOpts keeps one queued job per org and task.
func (OrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type orgWorker struct {
	river.WorkerDefaults[OrgArgs]
	s  *Service
	ep Endpoints
}

// Work runs one task for one org.
func (w *orgWorker) Work(ctx context.Context, job *river.Job[OrgArgs]) error {
	org := job.Args.Org
	switch job.Args.Task {
	case TaskFeed:
		for range MaxFeedBatches {
			r, err := w.s.ProcessFeed(ctx, org)
			if errors.Is(err, ErrCursorMoved) {
				return nil
			}
			if err != nil {
				return err
			}
			if r.Fired > 0 {
				w.s.d.Log.InfoContext(ctx, "automations.feed", slog.String("org", org.String()),
					slog.Int("events", r.Events), slog.Int("fired", r.Fired))
			}
			if r.To-r.From < int64(feed.MaxBatch) {
				return nil
			}
		}
		return nil
	case TaskSchedules:
		_, err := w.s.DispatchSchedules(ctx, org)
		return err
	case TaskConditions:
		_, err := w.s.EvaluateConditions(ctx, org)
		return err
	case TaskDeliveries:
		if w.ep == nil {
			return nil
		}
		_, err := w.ep.SendDue(ctx, org)
		return err
	case TaskJanitor:
		if err := w.s.Janitor(ctx, org); err != nil {
			return err
		}
		if w.ep != nil {
			_, err := w.ep.PruneReceipts(ctx, org)
			return err
		}
		return nil
	}
	return fmt.Errorf("automations: unknown task %q", job.Args.Task)
}

// DispatchArgs fans one task out to every active org.
type DispatchArgs struct {
	Task string `json:"task"`
}

// Kind implements river.JobArgs.
func (DispatchArgs) Kind() string { return "automations.triggers_dispatch" }

type dispatchWorker struct {
	river.WorkerDefaults[DispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *dispatchWorker) Work(ctx context.Context, job *river.Job[DispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("automations dispatch: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: OrgArgs{Org: r.Org, Task: job.Args.Task}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// Register adds the trigger workers to reg and returns their schedule.
func Register(reg *jobs.Registry, s *Service, ep Endpoints) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[OrgArgs](reg, &orgWorker{s: s, ep: ep}); err != nil {
		return nil, err
	}
	if err := jobs.Register[DispatchArgs](reg, &dispatchWorker{pool: s.d.Pool}); err != nil {
		return nil, err
	}
	var out []*river.PeriodicJob
	for _, task := range []string{TaskFeed, TaskSchedules, TaskConditions, TaskDeliveries, TaskJanitor} {
		out = append(out, river.NewPeriodicJob(river.PeriodicInterval(intervals[task]),
			func() (river.JobArgs, *river.InsertOpts) { return DispatchArgs{Task: task}, nil }, nil))
	}
	return out, nil
}

// Janitor expires queued triggers past their time to live and prunes
// expired dedupe claims (D16, D23).
func (s *Service) Janitor(ctx context.Context, org ids.OrgID) error {
	return s.d.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.ExpireQueuedTriggers(ctx, org); err != nil {
			return err
		}
		_, err := q.PruneAutomationDedupe(ctx, org)
		return err
	})
}
