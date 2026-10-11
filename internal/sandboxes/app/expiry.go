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

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// ExpiryInterval is how often open sessions past their expiry are ended.
const ExpiryInterval = time.Minute

// maxExpiredPerRun bounds one org's sweep; the next run takes the rest.
const maxExpiredPerRun = 500

// sweeper is the audit actor of the expiry sweep.
var sweeper = evdomain.Actor{Type: "system", ID: "sandbox-expiry"}

// ExpireSessions ends an org's open sessions past their expiry as EXPIRED
// and revokes their instances (design decision 9). A session pclaw never
// ended (killed, or a laptop asleep past the expiry) would otherwise stay
// open, and its instance in the agent's active cohort, which keeps every
// later closure of the agent from ENFORCED. It returns how many it ended.
func (s *Service) ExpireSessions(ctx context.Context, org ids.OrgID) (int, error) {
	n := 0
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		expired, err := q.ExpiredSandboxSessions(ctx, org, maxExpiredPerRun)
		if err != nil {
			return err
		}
		for _, sess := range expired {
			if _, err := s.end(ctx, q, sess, "EXPIRED", sweeper.ID, adomain.System); err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "sandbox.session_expired", Actor: sweeper, Outcome: audit.Success,
				Object: &audit.Object{Type: "sandbox_session", ID: sess.ID.String()}, Details: map[string]string{"agent_id": sess.AgentID.String()},
			}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// ExpiryOrgArgs asks for one org's expired sessions to be ended. Job args
// carry ids only (HR-056).
type ExpiryOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (ExpiryOrgArgs) Kind() string { return "sandbox.expiry_org" }

// InsertOpts keeps one queued job per org.
func (ExpiryOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type expiryOrgWorker struct {
	river.WorkerDefaults[ExpiryOrgArgs]
	svc *Service
	log *slog.Logger
}

func (w *expiryOrgWorker) Work(ctx context.Context, job *river.Job[ExpiryOrgArgs]) error {
	n, err := w.svc.ExpireSessions(ctx, job.Args.Org)
	if err == nil && n > 0 {
		w.log.InfoContext(ctx, "sandbox.sessions_expired", slog.String("org", job.Args.Org.String()), slog.Int("sessions", n))
	}
	return err
}

// ExpiryDispatchArgs fans the expiry sweep out to every active org.
type ExpiryDispatchArgs struct{}

// Kind implements river.JobArgs.
func (ExpiryDispatchArgs) Kind() string { return "sandbox.expiry_dispatch" }

type expiryDispatchWorker struct {
	river.WorkerDefaults[ExpiryDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *expiryDispatchWorker) Work(ctx context.Context, _ *river.Job[ExpiryDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("sandbox expiry: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: ExpiryOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterExpiry adds the expiry sweep's workers to reg and returns its
// schedule.
func RegisterExpiry(reg *jobs.Registry, svc *Service, log *slog.Logger) ([]*river.PeriodicJob, error) {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[ExpiryOrgArgs](reg, &expiryOrgWorker{svc: svc, log: log}); err != nil {
		return nil, err
	}
	if err := jobs.Register[ExpiryDispatchArgs](reg, &expiryDispatchWorker{pool: svc.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(ExpiryInterval),
			func() (river.JobArgs, *river.InsertOpts) { return ExpiryDispatchArgs{}, nil }, nil),
	}, nil
}
