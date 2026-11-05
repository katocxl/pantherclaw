// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package otlpexport

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Export scheduling (D1061).
const (
	// ExportInterval is how often every org's destinations are exported.
	ExportInterval = 30 * time.Second
	// maxStepsPerRun bounds one org job; the next run continues.
	maxStepsPerRun = 20
)

// ExportOrgArgs asks for one org's destinations to be exported. Job args
// carry ids only (HR-056).
type ExportOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (ExportOrgArgs) Kind() string { return "otlp.export_org" }

// InsertOpts keeps one queued job per org, on the notifications queue:
// slow collectors never hold up other jobs.
func (ExportOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: napp.Queue, UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// ExportOrg exports each due ACTIVE destination of org until it is caught
// up, fails, or the run's step budget is spent.
func (s *Service) ExportOrg(ctx context.Context, org ids.OrgID) error {
	var dests []ids.UUID
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		dests, err = dbq.New(tx).ListDueOTLPDestinations(ctx, org)
		return err
	}, db.ReadOnly())
	if err != nil || len(dests) == 0 {
		return err
	}
	steps := 0
	for _, id := range dests {
		for steps < maxStepsPerRun {
			steps++
			st, err := s.ExportOnce(ctx, org, id)
			if err != nil {
				s.log.ErrorContext(ctx, "otlp.export_failed", slog.String("destination", id.String()), pclog.Err(err))
				break
			}
			if !st.More || (st.Sent && !st.Delivered) {
				break
			}
		}
	}
	return nil
}

type exportOrgWorker struct {
	river.WorkerDefaults[ExportOrgArgs]
	svc *Service
}

func (w *exportOrgWorker) Work(ctx context.Context, job *river.Job[ExportOrgArgs]) error {
	return w.svc.ExportOrg(ctx, job.Args.Org)
}

// Timeout leaves room for the run's requests.
func (w *exportOrgWorker) Timeout(*river.Job[ExportOrgArgs]) time.Duration {
	return time.Duration(maxStepsPerRun+1) * RequestTimeout
}

// ExportDispatchArgs fans export out to every active org.
type ExportDispatchArgs struct{}

// Kind implements river.JobArgs.
func (ExportDispatchArgs) Kind() string { return "otlp.export_dispatch" }

type exportDispatchWorker struct {
	river.WorkerDefaults[ExportDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org; an org without destinations exits at once.
func (w *exportDispatchWorker) Work(ctx context.Context, _ *river.Job[ExportDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("otlp export dispatch: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: ExportOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterExport adds the exporter's workers to reg and returns its
// schedule: every org's destinations every 30 seconds (D1061).
func RegisterExport(reg *jobs.Registry, svc *Service) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[ExportOrgArgs](reg, &exportOrgWorker{svc: svc}); err != nil {
		return nil, err
	}
	if err := jobs.Register[ExportDispatchArgs](reg, &exportDispatchWorker{pool: svc.pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(ExportInterval),
			func() (river.JobArgs, *river.InsertOpts) { return ExportDispatchArgs{}, nil }, nil),
	}, nil
}
