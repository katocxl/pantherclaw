// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package recompute keeps each org's breach radius current (G0 M10 D27,
// F258): a per-org job reads the evidence feed from its compare-and-set
// position, records the last change that moves reach (grants, policy,
// coverage, connections, credentials, agents), and recomputes the
// snapshot when one happened since the current snapshot, or when the
// snapshot is older than Refresh (the observed view ages). Posture
// findings are reconciled with each new snapshot on editions that offer
// them. A dispatcher fans the job out to every active org (D3).
package recompute

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
	poapp "github.com/katocxl/pantherclaw/internal/posture/app"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// Timings.
const (
	// Interval is how often the dispatcher runs.
	Interval = 30 * time.Second
	// Refresh recomputes a snapshot this old even without a change.
	Refresh = time.Hour
	// Keep is how long old snapshots are kept (unless a finding cites one).
	Keep = 7 * 24 * time.Hour
	// maxBatches bounds the feed read per run (each ≤ feed.MaxBatch).
	maxBatches = 20
)

// moving lists the ledger kind prefixes of changes that move reach.
var moving = []string{
	"audit.grant", "audit.envelope", "audit.policy.published", "audit.policy.rollback", "audit.policy.exception",
	"audit.connection", "audit.credential", "audit.coverage", "audit.agent", "coverage.snapshot", "coverage.invalidation",
	// An automation enabled, paused or retired moves its ceiling (D37).
	"audit.automation",
}

// Moves reports whether an event of kind may change reach.
func Moves(kind string) bool {
	for _, p := range moving {
		if kind == p || strings.HasPrefix(kind, p+".") || strings.HasPrefix(kind, p+"_") {
			return true
		}
	}
	return false
}

// FailureSink records owned failures (core).
type FailureSink interface {
	ReportTx(ctx context.Context, tx db.TenantTx, f reflexdomain.Failure) (ids.UUID, bool, error)
}

// Service runs the per-org recomputation.
type Service struct {
	Pool     *db.Pool
	Ents     exapp.Entitlements
	Failures FailureSink
	// Findings is told of each posture finding a reconciliation touched
	// (the M16 suggestions' queue); nil: nobody.
	Findings poapp.FindingHook
	Log      *slog.Logger
}

// Result says what one run did.
type Result struct {
	Read       int
	Changed    bool
	Recomputed bool
	Posture    poapp.Summary
}

// Run reads the org's feed and recomputes when needed.
func (s *Service) Run(ctx context.Context, org ids.OrgID) (Result, error) {
	ctx = tenantctx.WithOrg(ctx, org) // the org's entitlements (G0 UI D9)
	var res Result
	if err := exapp.Entitled(ctx, s.Ents); err != nil {
		// A lapsed edition stops quietly and records one failure (D5);
		// the failure stays one while it is open.
		if errors.Is(err, exapp.ErrEdition) {
			return res, s.lapsed(ctx, org)
		}
		return res, err
	}
	posture := false
	if s.Ents != nil {
		if e, err := s.Ents.Current(ctx); err == nil {
			posture = e.PostureFindings() // computed on Team too (G0 M24 D201)
		}
	}
	due := false
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		ch, err := q.GetExposureChanges(ctx, org)
		if db.IsNoRows(err) {
			ch = dbq.PcExposureChange{OrgID: org}
		} else if err != nil {
			return err
		}
		pos, change := ch.ReadSeq, int64(0)
		for range maxBatches {
			evs, err := (feed.Reader{}).After(ctx, tx, pos, feed.MaxBatch)
			if err != nil {
				return err
			}
			for _, e := range evs {
				pos = e.Seq
				if Moves(e.Kind) {
					change = e.Seq
				}
			}
			res.Read += len(evs)
			if len(evs) < feed.MaxBatch {
				break
			}
		}
		if change > 0 {
			res.Changed = true
			if err := q.RecordExposureChange(ctx, org, change); err != nil {
				return err
			}
		}
		if pos != ch.ReadSeq {
			n, err := q.AdvanceExposureRead(ctx, org, pos, ch.ReadSeq)
			if err != nil {
				return err
			}
			if n == 0 {
				return errMoved // another run advanced it: this one's reads are void
			}
		}
		snap, err := q.LatestExposureSnapshot(ctx, org)
		switch {
		case db.IsNoRows(err):
			due = true
		case err != nil:
			return err
		default:
			now, err := q.DBNow(ctx)
			if err != nil {
				return err
			}
			due = res.Changed || snap.Stale || now.Sub(snap.ComputedAt) >= Refresh
		}
		return nil
	})
	if errors.Is(err, errMoved) {
		return res, nil
	} else if err != nil || !due {
		return res, err
	}
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		head, err := (feed.Reader{}).Head(ctx, tx)
		if err != nil {
			return err
		}
		cause := "change"
		if !res.Changed {
			cause = "schedule"
		}
		rec, err := exapp.Recompute(ctx, tx, cause, head)
		if err != nil {
			return err
		}
		res.Recomputed = true
		if posture {
			if res.Posture, err = poapp.ReconcileWith(ctx, tx, rec, s.Findings); err != nil {
				return err
			}
		}
		_, err = dbq.New(tx).PruneExposureSnapshots(ctx, org, rec.Snapshot.ComputedAt.Add(-Keep))
		return err
	})
	return res, err
}

var errMoved = errors.New("exposure: feed position moved")

func (s *Service) lapsed(ctx context.Context, org ids.OrgID) error {
	if s.Failures == nil {
		return nil
	}
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		// Only an org that once had breach radius has something to lose.
		if _, err := dbq.New(tx).LatestExposureSnapshot(ctx, org); db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		_, _, err := s.Failures.ReportTx(ctx, tx, reflexdomain.Failure{
			Org: org, Kind: "exposure.edition_lapsed", DedupeKey: "exposure.edition_lapsed",
			Summary:  "Breach radius stopped recomputing: the edition no longer includes it. The last snapshot is stale.",
			NextStep: "Renew a Team or higher licence, or treat the exposure views as out of date.",
		})
		return err
	})
}

// OrgArgs asks for one org's recomputation. Job args carry ids only
// (HR-056).
type OrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (OrgArgs) Kind() string { return "exposure.recompute_org" }

// InsertOpts keeps one queued job per org (D3).
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
	svc *Service
}

func (w *orgWorker) Work(ctx context.Context, job *river.Job[OrgArgs]) error {
	res, err := w.svc.Run(ctx, job.Args.Org)
	if err == nil && res.Recomputed {
		w.svc.Log.InfoContext(ctx, "exposure.recomputed", slog.String("org", job.Args.Org.String()),
			slog.Bool("changed", res.Changed), slog.Int("events", res.Read))
	}
	return err
}

// DispatchArgs fans the recomputation out to every active org.
type DispatchArgs struct{}

// Kind implements river.JobArgs.
func (DispatchArgs) Kind() string { return "exposure.recompute_dispatch" }

type dispatchWorker struct {
	river.WorkerDefaults[DispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *dispatchWorker) Work(ctx context.Context, _ *river.Job[DispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("exposure recompute: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: OrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// Register adds the workers to reg and returns the schedule.
func Register(reg *jobs.Registry, svc *Service) ([]*river.PeriodicJob, error) {
	if svc.Log == nil {
		svc.Log = pclog.Discard()
	}
	if err := jobs.Register[OrgArgs](reg, &orgWorker{svc: svc}); err != nil {
		return nil, err
	}
	if err := jobs.Register[DispatchArgs](reg, &dispatchWorker{pool: svc.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(Interval),
			func() (river.JobArgs, *river.InsertOpts) { return DispatchArgs{}, nil }, nil),
	}, nil
}
