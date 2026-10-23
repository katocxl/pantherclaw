// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type RequestID struct{}

func (RequestID) KindName() string { return "data request" }

type ExportArgs struct {
	Org     ids.OrgID         `json:"org"`
	Request ids.ID[RequestID] `json:"request"`
}

func (ExportArgs) Kind() string                 { return "data.export" }
func (ExportArgs) InsertOpts() river.InsertOpts { return unique() }

type DeleteArgs struct {
	Org     ids.OrgID         `json:"org"`
	Request ids.ID[RequestID] `json:"request"`
}

func (DeleteArgs) Kind() string                 { return "data.delete_org" }
func (DeleteArgs) InsertOpts() river.InsertOpts { return unique() }

type DailyArgs struct{}

func (DailyArgs) Kind() string { return "data.daily" }

type OrgArgs struct {
	Org ids.OrgID `json:"org"`
}

func (OrgArgs) Kind() string                 { return "data.daily_org" }
func (OrgArgs) InsertOpts() river.InsertOpts { return unique() }

func unique() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning, rivertype.JobStateScheduled, rivertype.JobStateRetryable,
	}}}
}
func enqueue(ctx context.Context, jc *jobs.Client, tx db.TenantTx, org ids.OrgID, id ids.UUID, del bool, at time.Time) error {
	if jc == nil {
		return errors.New("datarequests: jobs unavailable")
	}
	rid, err := ids.FromUUID[RequestID](id)
	if err != nil {
		return err
	}
	opts := &river.InsertOpts{ScheduledAt: at}
	if del {
		return jobs.InsertTx(ctx, jc, tx, DeleteArgs{Org: org, Request: rid}, opts)
	}
	return jobs.InsertTx(ctx, jc, tx, ExportArgs{Org: org, Request: rid}, opts)
}

type exportWorker struct {
	river.WorkerDefaults[ExportArgs]
	s *Service
}

func (w *exportWorker) Timeout(*river.Job[ExportArgs]) time.Duration { return 9 * time.Minute }
func (w *exportWorker) Work(ctx context.Context, j *river.Job[ExportArgs]) error {
	return w.s.Build(ctx, j.Args.Org, j.Args.Request.UUID())
}

type deleteWorker struct {
	river.WorkerDefaults[DeleteArgs]
	s *Service
}

func (w *deleteWorker) Timeout(*river.Job[DeleteArgs]) time.Duration { return 9 * time.Minute }
func (w *deleteWorker) Work(ctx context.Context, j *river.Job[DeleteArgs]) error {
	err := w.s.DeleteOrg(ctx, j.Args.Org, j.Args.Request.UUID())
	if errors.Is(err, ErrHeld) {
		return river.JobSnooze(24 * time.Hour)
	}
	if errors.Is(err, ErrAwaitingSecurityCopy) {
		return river.JobSnooze(time.Minute)
	}
	if errors.Is(err, ErrRole) {
		return river.JobSnooze(time.Hour)
	}
	return err
}

type dailyWorker struct {
	river.WorkerDefaults[DailyArgs]
	s *Service
}

func (w *dailyWorker) Work(ctx context.Context, _ *river.Job[DailyArgs]) error {
	refs, err := w.s.Pool.CrossOrgList(ctx, db.ListAllOrgs, 10000)
	if err != nil {
		return err
	}
	if len(refs) >= 10000 {
		return errors.New("datarequests: organisation lister reached its cap")
	}
	for _, r := range refs {
		if r.Org == ids.PlatformOrg {
			continue
		}
		if _, err := w.s.Jobs.Insert(ctx, OrgArgs{Org: r.Org}, nil); err != nil {
			return err
		}
	}
	return nil
}

type orgWorker struct {
	river.WorkerDefaults[OrgArgs]
	s *Service
}

func (w *orgWorker) Work(ctx context.Context, j *river.Job[OrgArgs]) error {
	return w.s.Daily(ctx, j.Args.Org)
}
func Register(reg *jobs.Registry, s *Service) error {
	if err := jobs.Register[ExportArgs](reg, &exportWorker{s: s}); err != nil {
		return err
	}
	if err := jobs.Register[DeleteArgs](reg, &deleteWorker{s: s}); err != nil {
		return err
	}
	if err := jobs.Register[DailyArgs](reg, &dailyWorker{s: s}); err != nil {
		return err
	}
	return jobs.Register[OrgArgs](reg, &orgWorker{s: s})
}
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(24*time.Hour), func() (river.JobArgs, *river.InsertOpts) { return DailyArgs{}, nil }, &river.PeriodicJobOpts{RunOnStart: true})}
}
