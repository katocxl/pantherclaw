// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package promotions

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Provisional promotions (D80, founder decision F7): a new production agent
// has no traffic, so no coverage record, until it holds a grant. When every
// check passes but COVERAGE, and only because no record exists yet, a
// person may promote it PROVISIONAL for ProvisionalFor; grants under it end
// with it. The sweep makes it ACTIVE once its routes read ENFORCED or
// PARTIAL (not lapsed), or EXPIRED at its expiry with an owned failure to
// the agent's owner.

// FailureLapsed is the owned failure of a provisional promotion that
// expired before coverage appeared.
const FailureLapsed = "promotion.provisional_lapsed"

// FailureSink records owned failures (reflex/failures.Sink).
type FailureSink interface {
	Report(ctx context.Context, tx pgx.Tx, f reflexdomain.Failure) (ids.UUID, error)
}

// system is the actor of the sweep's changes.
var system = evdomain.Actor{Type: "system", ID: "promotions"}

// confirm makes a provisional promotion ACTIVE (audited).
func (s *Service) confirm(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, p dbq.PcAgentPromotion) (dbq.PcAgentPromotion, error) {
	row, err := dbq.New(tx).ConfirmAgentPromotion(ctx, p.OrgID, p.ID)
	if err != nil {
		return row, err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "agent.promotion_confirmed", Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "agent", ID: p.AgentID.String()},
		Details: map[string]string{
			"promotion": p.ID.String(), "environment": p.EnvironmentID.String(), "operation": p.Operation,
		},
	})
	return row, err
}

// expire records a lapsed provisional promotion EXPIRED (audited) and
// tells the agent's owner through an owned failure.
func (s *Service) expire(ctx context.Context, tx db.TenantTx, p dbq.PcAgentPromotion) error {
	q := dbq.New(tx)
	row, err := q.ExpireAgentPromotion(ctx, p.OrgID, p.ID)
	if err != nil {
		return err
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "agent.promotion_expired", Actor: system, Outcome: audit.Success,
		Object: &audit.Object{Type: "agent", ID: p.AgentID.String()},
		Details: map[string]string{
			"promotion": p.ID.String(), "environment": p.EnvironmentID.String(), "operation": p.Operation,
			"expires_at": row.ExpiresAt.UTC().Format(time.RFC3339),
		},
	}); err != nil {
		return err
	}
	if s.Failures == nil {
		return nil
	}
	f := reflexdomain.Failure{
		Org: p.OrgID, Kind: FailureLapsed,
		Summary: fmt.Sprintf("The provisional production promotion of agent %s for %s expired before any coverage was recorded; "+
			"new grants for it are refused.", p.AgentID, p.Operation),
		NextStep:  "Check that the agent's traffic for the operation goes through an enforcing connection, then promote it again.",
		Scope:     []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: p.AgentID.String()}},
		DedupeKey: FailureLapsed + ":" + p.ID.String(),
	}
	if a, err := q.GetAgent(ctx, p.OrgID, p.AgentID); err == nil && a.OwnerUserID != nil {
		f.Owner = &reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: a.OwnerUserID.String()}
	} else if err != nil {
		return err
	}
	_, err = s.Failures.Report(ctx, tx.Pgx(), f)
	return err
}

// pending says on each provisional promotion's COVERAGE check how long it
// stays provisional.
func pending(rs []Readiness) {
	for i, r := range rs {
		if r.Promotion == nil || r.Promotion.State != StateProvisional || r.Promotion.ExpiresAt == nil {
			continue
		}
		for j, c := range r.Checks {
			if c.Name == CheckCoverage && !c.Passed {
				rs[i].Checks[j].Detail = "coverage pending until " + r.Promotion.ExpiresAt.UTC().Format(time.RFC3339)
			}
		}
	}
}

// maxSweep bounds one org's sweep; the next run takes the rest.
const maxSweep = 200

// SweepInterval is how often provisional promotions are swept (D80). A
// provisional promotion past its expiry covers nothing whether or not the
// sweep has run: the gate reads only those the database clock has not
// passed.
const SweepInterval = 5 * time.Minute

// Sweep confirms the org's provisional promotions whose coverage appeared
// and expires those past their expiry. It returns how many of each.
func (s *Service) Sweep(ctx context.Context, org ids.OrgID) (confirmed, expired int, err error) {
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ProvisionalPromotions(ctx, org, maxSweep)
		if err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		var cat *catalog
		subjects := map[ids.UUID]*subject{}
		for _, p := range rows {
			if !now.Before(*p.ExpiresAt) {
				if err := s.expire(ctx, tx, p); err != nil {
					return err
				}
				expired++
				continue
			}
			sub, ok := subjects[p.AgentID]
			if !ok {
				if cat == nil {
					c, err := loadCatalog(ctx, q, s.Packages, org)
					if err != nil {
						return err
					}
					cat = &c
				}
				row, err := q.PromotionSubject(ctx, org, p.AgentID)
				if err != nil {
					return err
				}
				if sub, err = load(ctx, q, org, row, p.EnvironmentID, *cat); err != nil {
					return err
				}
				subjects[p.AgentID] = sub
			}
			c, err := sub.coverage(ctx, q, p.Operation, now)
			if err != nil {
				return err
			}
			if c.Passed {
				if _, err := s.confirm(ctx, tx, system, p); err != nil {
					return err
				}
				confirmed++
			}
		}
		return nil
	})
	return confirmed, expired, err
}

// SweepOrgArgs asks for one org's provisional promotions to be swept. Job
// args carry ids only (HR-056).
type SweepOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SweepOrgArgs) Kind() string { return "promotions.provisional_sweep_org" }

// InsertOpts keeps one queued job per org.
func (SweepOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type sweepOrgWorker struct {
	river.WorkerDefaults[SweepOrgArgs]
	svc *Service
	log *slog.Logger
}

func (w *sweepOrgWorker) Work(ctx context.Context, job *river.Job[SweepOrgArgs]) error {
	confirmed, expired, err := w.svc.Sweep(ctx, job.Args.Org)
	if err == nil && confirmed+expired > 0 {
		w.log.InfoContext(ctx, "promotions.provisional_swept", slog.String("org", job.Args.Org.String()),
			slog.Int("confirmed", confirmed), slog.Int("expired", expired))
	}
	return err
}

// SweepDispatchArgs fans the sweep out to every active org.
type SweepDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SweepDispatchArgs) Kind() string { return "promotions.provisional_sweep_dispatch" }

type sweepDispatchWorker struct {
	river.WorkerDefaults[SweepDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *sweepDispatchWorker) Work(ctx context.Context, _ *river.Job[SweepDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("promotions sweep: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SweepOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterSweep adds the sweep's workers to reg and returns its schedule.
func RegisterSweep(reg *jobs.Registry, svc *Service, log *slog.Logger) ([]*river.PeriodicJob, error) {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[SweepOrgArgs](reg, &sweepOrgWorker{svc: svc, log: log}); err != nil {
		return nil, err
	}
	if err := jobs.Register[SweepDispatchArgs](reg, &sweepDispatchWorker{pool: svc.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepDispatchArgs{}, nil }, nil),
	}, nil
}
