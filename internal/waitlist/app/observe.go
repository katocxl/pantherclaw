// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// ObserveInterval is the window of closed entries each observation reads;
// observeLag leaves the decisions of a window time to commit.
const (
	ObserveInterval = 5 * time.Minute
	observeLag      = time.Minute
)

// Histograms are the server's waitlist metrics (G0 M5 part 2, decision
// 18): time to first response and to decision, as OpenTelemetry histograms
// whose only attributes are the entry's kind and state, never an org
// (T-042).
type Histograms struct {
	firstResponse, decision metric.Float64Histogram
}

// NewHistograms creates the histograms on m, or on the global meter
// provider when m is nil.
func NewHistograms(m metric.Meter) (*Histograms, error) {
	if m == nil {
		m = otel.Meter("github.com/katocxl/pantherclaw/internal/waitlist")
	}
	first, err := m.Float64Histogram("pantherclaw.waitlist.first_response.duration", metric.WithUnit("s"),
		metric.WithDescription("Time from a waitlist entry's creation to its first response."))
	if err != nil {
		return nil, err
	}
	decision, err := m.Float64Histogram("pantherclaw.waitlist.decision.duration", metric.WithUnit("s"),
		metric.WithDescription("Time from a waitlist entry's creation to its approval or rejection."))
	if err != nil {
		return nil, err
	}
	return &Histograms{firstResponse: first, decision: decision}, nil
}

// record adds closed entries: a first response when someone responded,
// a decision when the entry was approved or rejected.
func (h *Histograms) record(ctx context.Context, rows []dbq.ClosedEntriesBetweenRow) {
	for _, r := range rows {
		attrs := metric.WithAttributes(attribute.String("kind", r.Kind), attribute.String("state", r.State))
		if r.FirstS >= 0 {
			h.firstResponse.Record(ctx, r.FirstS, attrs)
		}
		if r.State != wdomain.StateExpired {
			h.decision.Record(ctx, r.DecisionS, attrs)
		}
	}
}

// ObserveArgs asks for the entries closed in the window ending at Until
// to be recorded. Job args carry times only (HR-056).
type ObserveArgs struct {
	Until time.Time `json:"until"`
}

// Kind implements river.JobArgs.
func (ObserveArgs) Kind() string { return "waitlist.observe" }

// InsertOpts records each window once, also after its job completed.
func (ObserveArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStateCompleted, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type observeWorker struct {
	river.WorkerDefaults[ObserveArgs]
	pool *db.Pool
	h    *Histograms
}

// Work reads each active org's entries closed in the window, listed
// through the audited lister (HR-054), and records them without the org.
// A retry may record a window's earlier orgs twice.
func (w *observeWorker) Work(ctx context.Context, job *river.Job[ObserveArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil {
		return err
	}
	since := job.Args.Until.Add(-ObserveInterval)
	for _, r := range refs {
		var rows []dbq.ClosedEntriesBetweenRow
		if err := w.pool.InTenantTx(ctx, r.Org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			rows, err = dbq.New(tx).ClosedEntriesBetween(ctx, r.Org, &since, &job.Args.Until)
			return err
		}, db.ReadOnly()); err != nil {
			return err
		}
		w.h.record(ctx, rows)
	}
	return nil
}

// RegisterObserver adds the histogram worker to reg.
func RegisterObserver(reg *jobs.Registry, pool *db.Pool, h *Histograms) error {
	return jobs.Register[ObserveArgs](reg, &observeWorker{pool: pool, h: h})
}

// ObservePeriodicJobs returns the observation schedule: every interval,
// the last whole window that ended at least a minute ago.
func ObservePeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(ObserveInterval), func() (river.JobArgs, *river.InsertOpts) {
			return ObserveArgs{Until: time.Now().Add(-observeLag).Truncate(ObserveInterval).UTC()}, nil
		}, nil),
	}
}
