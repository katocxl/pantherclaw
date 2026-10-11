// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
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
// and marks the invalidations reassessed, entering each in the ledger. A
// scope that fails is rolled back alone, logged and skipped, and the
// invalidations that touched it stay pending; a failed transaction retries
// the job, and nothing is marked until its snapshots are recorded.
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
		done := make([]dbq.PcCoverageInvalidation, 0, len(pending))
		touched := map[ids.UUID][]domain.Scope{}
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
			touched[inv.ID] = scopes
			done = append(done, inv)
		}
		expired, err := q.ExpiredEnforcedCoverageScopes(ctx, org, maxScopesPerJob)
		if err != nil {
			return err
		}
		for _, x := range expired {
			add(domain.Scope{Agent: x.AgentID, Connection: x.ConnectionID, Operation: x.Operation}, nil)
		}
		pkgs := packages{}
		failed := map[domain.Scope]bool{}
		for _, sc := range order {
			recorded, skip, err := s.reassessIsolated(ctx, tx, sc, causes[sc], pkgs)
			if err != nil {
				return err
			}
			if skip != nil {
				failed[sc] = true
				out.Skipped++
				s.log().WarnContext(ctx, "coverage.reassess: scope skipped", slog.String("org", org.String()),
					slog.String("agent", sc.Agent.String()), slog.String("connection", sc.Connection.String()),
					slog.String("operation", sc.Operation), slog.String("error", skip.Error()))
				continue
			}
			out.Scopes++
			if recorded {
				out.Snapshots++
			}
		}
		// An invalidation is entered in the ledger and marked reassessed only
		// once every scope it touched was reassessed; a skipped one stays
		// pending and the next job tries again.
		for _, inv := range done {
			if slices.ContainsFunc(touched[inv.ID], func(sc domain.Scope) bool { return failed[sc] }) {
				continue
			}
			if err := s.enterInvalidation(ctx, tx, inv); err != nil {
				return err
			}
		}
		// With the changes they saw marked, the agents' protection is derived
		// from their scopes as they read now.
		return s.deriveAgents(ctx, tx, slices.DeleteFunc(slices.Clone(order), func(sc domain.Scope) bool { return failed[sc] }),
			s.now(), pkgs)
	})
	return out, err
}

// reassessIsolated reassesses one scope inside a savepoint, so a scope
// whose evidence cannot be read or recorded is rolled back alone and
// reported in skip. err is a failure of the transaction itself.
func (s *Service) reassessIsolated(ctx context.Context, tx db.TenantTx, sc domain.Scope, cause *ids.UUID, pkgs packages,
) (recorded bool, skip, err error) {
	if _, err := tx.Exec(ctx, "SAVEPOINT coverage_scope"); err != nil {
		return false, nil, err
	}
	recorded, skip = s.reassess(ctx, tx, sc, cause, Actor, pkgs)
	if skip != nil {
		if ctx.Err() != nil {
			return false, nil, skip
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT coverage_scope"); err != nil {
			return false, nil, errors.Join(skip, err)
		}
		return false, skip, nil
	}
	_, err = tx.Exec(ctx, "RELEASE SAVEPOINT coverage_scope")
	return recorded, nil, err
}

// enterInvalidation appends a reassessed invalidation to the ledger as a
// coverage.invalidation entry, which a lapsed claim names (HR-217), and
// marks it reassessed with that entry.
func (s *Service) enterInvalidation(ctx context.Context, tx db.TenantTx, inv dbq.PcCoverageInvalidation) error {
	body, err := evdomain.CanonicalBody(InvalidationEntry{
		V: 1, ID: inv.ID, Connection: inv.ConnectionID, Agent: inv.AgentID, Kind: inv.Kind, Subject: inv.SubjectID,
		OccurredAt: evdomain.Timestamp(inv.OccurredAt),
	})
	if err != nil {
		return err
	}
	entry, err := ledger.Append(ctx, tx, InvalidationLedgerKind, Actor, body)
	if err != nil {
		return err
	}
	_, err = dbq.New(tx).EnterCoverageInvalidation(ctx, &entry.ID, tx.OrgID(), inv.ID)
	return err
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
		river.NewPeriodicJob(river.PeriodicInterval(f.ReassessEvery),
			func() (river.JobArgs, *river.InsertOpts) { return ReassessDispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
}
