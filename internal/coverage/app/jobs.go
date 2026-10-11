// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// The reassess job (HR-211, F441, F453). A periodic dispatcher lists the
// orgs with something to reassess through the audited cross-org lister
// and enqueues one unique job per org (HR-054, HR-056: ids only); the job
// reads new traffic, reassesses the scopes of every pending invalidation
// and of every lapsed ENFORCED snapshot in that org's tenant transaction,
// and marks the invalidations reassessed. A failed job retries; nothing is
// marked until its snapshots are recorded.
const (
	// ListReassess is the lister purpose coverage_reassess (migration
	// 00087).
	ListReassess db.ListerPurpose = "coverage_reassess"

	maxOrgsPerDispatch = 1000
	// maxPendingPerJob and maxScopesPerJob bound one job; the next
	// dispatch continues.
	maxPendingPerJob = 200
	maxScopesPerJob  = 500
	reassessTimeout  = 5 * time.Minute
)

// Actor is who records the snapshots of the reassess job.
var Actor = evdomain.Actor{Type: "system", ID: "coverage-reassess"}

// ReassessOrgArgs asks for one org's reassessment.
type ReassessOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (ReassessOrgArgs) Kind() string { return "coverage.reassess_org" }

// InsertOpts keeps one job per org queued at a time.
func (ReassessOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// ReassessDispatchArgs asks for the orgs to reassess.
type ReassessDispatchArgs struct{}

// Kind implements river.JobArgs.
func (ReassessDispatchArgs) Kind() string { return "coverage.reassess_dispatch" }

// ReassessOrg reassesses one org (the job's work).
func (s *Service) ReassessOrg(ctx context.Context, org ids.OrgID) (Reassessed, error) {
	var out Reassessed
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		causes := map[domain.Scope]*ids.UUID{}
		var order []domain.Scope
		add := func(sc domain.Scope, cause *ids.UUID) {
			if _, ok := causes[sc]; !ok {
				causes[sc] = cause
				order = append(order, sc)
			}
		}
		traffic, err := s.RefreshTraffic(ctx, tx)
		if err != nil {
			return err
		}
		for _, sc := range traffic {
			add(sc, nil)
		}
		pending, err := q.PendingCoverageInvalidations(ctx, org, maxPendingPerJob)
		if err != nil {
			return err
		}
		done := make([]ids.UUID, 0, len(pending))
		for _, inv := range pending {
			scopes, err := scopesOf(ctx, q, org, inv.ConnectionID, inv.AgentID)
			if err != nil {
				return err
			}
			if len(done) > 0 && len(order)+len(scopes) > maxScopesPerJob {
				break // the next job continues with this invalidation
			}
			for _, sc := range scopes {
				add(sc, &inv.ID)
			}
			done = append(done, inv.ID)
		}
		expired, err := q.ExpiredEnforcedCoverageScopes(ctx, org, maxScopesPerJob)
		if err != nil {
			return err
		}
		for _, x := range expired {
			add(domain.Scope{Agent: x.AgentID, Connection: x.ConnectionID, Operation: x.Operation}, nil)
		}
		pkgs := packages{}
		for _, sc := range order {
			recorded, err := s.reassess(ctx, tx, sc, causes[sc], Actor, pkgs)
			if err != nil {
				return fmt.Errorf("coverage: reassess %v: %w", sc, err)
			}
			out.Scopes++
			if recorded {
				out.Snapshots++
			}
		}
		if len(done) > 0 {
			_, err = q.MarkCoverageInvalidationsReassessed(ctx, org, done)
		}
		return err
	})
	return out, err
}

type reassessWorker struct {
	river.WorkerDefaults[ReassessOrgArgs]
	svc *Service
}

func (w *reassessWorker) Timeout(*river.Job[ReassessOrgArgs]) time.Duration { return reassessTimeout }

func (w *reassessWorker) Work(ctx context.Context, job *river.Job[ReassessOrgArgs]) error {
	_, err := w.svc.ReassessOrg(ctx, job.Args.Org)
	return err
}

type dispatcher struct {
	river.WorkerDefaults[ReassessDispatchArgs]
	pool *db.Pool
}

func (w *dispatcher) Work(ctx context.Context, _ *river.Job[ReassessDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, ListReassess, maxOrgsPerDispatch)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("coverage: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: ReassessOrgArgs{Org: r.Org}})
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("coverage: enqueue: %w", err)
	}
	return nil
}

// Register adds the reassess workers to reg.
func Register(reg *jobs.Registry, svc *Service) error {
	if err := jobs.Register[ReassessOrgArgs](reg, &reassessWorker{svc: svc}); err != nil {
		return err
	}
	return jobs.Register[ReassessDispatchArgs](reg, &dispatcher{pool: svc.Pool})
}

// PeriodicJobs returns the dispatcher's schedule: every reassess interval
// of the freshness contract.
func PeriodicJobs(f domain.Freshness) []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(f.ReassessInterval),
			func() (river.JobArgs, *river.InsertOpts) { return ReassessDispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
}
