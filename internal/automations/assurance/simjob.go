// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Simulation errors.
var (
	ErrRange = pcerr.New(pcerr.InvalidArgument, "SIMULATION_RANGE_INVALID",
		"a simulation covers a past period of at most 30 days")
	ErrJobs = pcerr.New(pcerr.Unavailable, "SIMULATION_UNAVAILABLE", "this server cannot queue simulations")
)

// Simulation limits.
const (
	// simBatches bounds the feed a simulation reads (each feed.MaxBatch).
	simBatches = 200
	// receiptsKept is how long inbound receipts are kept (D21).
	receiptsKept = 7 * 24 * time.Hour
	// SimJobTimeout bounds one simulation run.
	SimJobTimeout = 5 * time.Minute
)

// SimulateArgs runs one automation simulation; ids only (HR-056).
type SimulateArgs struct {
	Org        ids.OrgID `json:"org"`
	Simulation ids.UUID  `json:"simulation"`
}

// Kind implements river.JobArgs.
func (SimulateArgs) Kind() string { return "automation_simulate" }

// InsertOpts keeps one job per simulation while it waits or runs.
func (SimulateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// Simulation is a stored simulation.
type Simulation struct {
	ID, Version ids.UUID
	From, To    time.Time
	State       string
	Results     *SimResults
	Error       string
	CreatedAt   time.Time
	FinishedAt  *time.Time
}

// StartSimulation queues a simulation of a version over [from, to) (D35).
func (s *Service) StartSimulation(ctx context.Context, versionID ids.UUID, from, to time.Time) (ids.UUID, error) {
	c, err := caller(ctx, td.PermAutomationManage)
	if err != nil {
		return ids.UUID{}, err
	}
	if err := s.edition(ctx, false); err != nil {
		return ids.UUID{}, err
	}
	now := s.now().Now()
	if !to.After(from) || to.Sub(from) > MaxSimulationRange || to.After(now.Add(time.Minute)) {
		return ids.UUID{}, ErrRange
	}
	if s.Jobs == nil {
		return ids.UUID{}, ErrJobs
	}
	id := ids.NewV7()
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		v, _, err := version(ctx, q, c.Org, versionID)
		if err != nil {
			return err
		}
		if err := q.InsertAutomationSimulation(ctx, dbq.InsertAutomationSimulationParams{
			OrgID: c.Org, ID: id, VersionID: versionID, FromAt: from.UTC(), ToAt: to.UTC(), RequestedBy: c.Principal.ID,
		}); err != nil {
			return err
		}
		if err := jobs.InsertTx(ctx, s.Jobs, tx, SimulateArgs{Org: c.Org, Simulation: id}, nil); err != nil {
			return err
		}
		return record(ctx, tx, c, "automation.simulation_started", versionID, map[string]string{
			"automation": v.AutomationID.String(), "simulation": id.String(),
			"from": from.UTC().Format(time.RFC3339), "to": to.UTC().Format(time.RFC3339),
		})
	})
	return id, err
}

// GetSimulation returns a simulation.
func (s *Service) GetSimulation(ctx context.Context, id ids.UUID) (Simulation, error) {
	c, err := caller(ctx, td.PermAutomationRead)
	if err != nil {
		return Simulation{}, err
	}
	if err := s.edition(ctx, false); err != nil {
		return Simulation{}, err
	}
	var out Simulation
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetAutomationSimulation(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		out = Simulation{
			ID: r.ID, Version: r.VersionID, From: r.FromAt, To: r.ToAt, State: r.State, CreatedAt: r.CreatedAt,
			FinishedAt: r.FinishedAt,
		}
		if r.Error != nil {
			out.Error = *r.Error
		}
		if len(r.Results) > 0 {
			var res SimResults
			if err := json.Unmarshal(r.Results, &res); err != nil {
				return fmt.Errorf("assurance: stored simulation %s: %w", r.ID, err)
			}
			out.Results = &res
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// approveRoles are the built-in roles holding automation.approve.
func approveRoles() []string {
	var out []string
	for _, r := range td.Roles() {
		if r.Has(td.PermAutomationApprove) {
			out = append(out, string(r.Name))
		}
	}
	return out
}

// history reads what a simulation of def over [from, to) needs, read-only.
func history(ctx context.Context, tx db.TenantTx, def *autodomain.Definition, from, to, now time.Time) (History, error) {
	q, org := dbq.New(tx), tx.OrgID()
	var h History
	w := def.When
	if w.Event != nil || w.Threshold != nil {
		start := from
		if w.Threshold != nil {
			start = from.Add(-w.Threshold.Over.D())
		}
		pos, err := q.AssuranceFeedSeqAt(ctx, org, start)
		if err != nil {
			return h, err
		}
		if pos >= 0 {
			h.EventsTruncated = true
		read:
			for range simBatches {
				evs, err := (feed.Reader{}).After(ctx, tx, pos, feed.MaxBatch)
				if err != nil {
					return h, err
				}
				for _, e := range evs {
					pos = e.Seq
					if !e.OccurredAt.Before(to) {
						h.EventsTruncated = false
						break read
					}
					h.Events = append(h.Events, e)
				}
				if len(evs) < feed.MaxBatch {
					h.EventsTruncated = false
					break read
				}
			}
		}
	}
	if w.Inbound != nil {
		rs, err := q.AssuranceReceipts(ctx, dbq.AssuranceReceiptsParams{
			OrgID: org, SourceID: w.Inbound.Source.UUID(), Type: w.Inbound.Type, FromAt: from, ToAt: to,
		})
		if err != nil {
			return h, err
		}
		for _, r := range rs {
			h.Receipts = append(h.Receipts, Receipt{Source: r.SourceID, Type: r.Type, At: r.ReceivedAt})
		}
		h.ReceiptsFrom = now.Add(-receiptsKept)
	}
	if w.Condition != nil {
		gs, err := q.AssuranceGrantExpiries(ctx, org, from, to.Add(7*24*time.Hour))
		if err != nil {
			return h, err
		}
		for _, g := range gs {
			p := ""
			switch {
			case g.PrincipalSaID != nil:
				p = "service_account:" + g.PrincipalSaID.String()
			case g.PrincipalUserID != nil:
				p = "user:" + g.PrincipalUserID.String()
			}
			h.Grants = append(h.Grants, GrantExpiry{Grant: g.ID, Agent: g.AgentID, Principal: p, TaskRef: g.TaskRef, ExpiresAt: g.ExpiresAt})
		}
	}
	approvers, err := q.OrgUsersWithRoles(ctx, org, approveRoles())
	if err != nil {
		return h, err
	}
	h.Approvers = len(approvers)
	return h, nil
}

// RunSimulation runs a queued simulation: RUNNING, replay, DONE (or
// FAILED). It writes only the simulation's own row (HR-288).
func (s *Service) RunSimulation(ctx context.Context, org ids.OrgID, id ids.UUID) error {
	var started bool
	if err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).StartAutomationSimulation(ctx, org, id)
		started = n == 1
		return err
	}); err != nil || !started {
		return err
	}
	var res SimResults
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sim, err := q.GetAutomationSimulation(ctx, org, id)
		if err != nil {
			return err
		}
		_, def, err := version(ctx, q, org, sim.VersionID)
		if err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		h, err := history(ctx, tx, def, sim.FromAt, sim.ToAt, now)
		if err != nil {
			return err
		}
		res = Replay(ctx, def, h, sim.FromAt, sim.ToAt)
		return nil
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	body, err := json.Marshal(res, json.Deterministic(true))
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).FinishAutomationSimulation(ctx, body, org, id)
		return err
	})
}

// FailSimulation marks a simulation FAILED with a stable reason.
func (s *Service) FailSimulation(ctx context.Context, org ids.OrgID, id ids.UUID, reason string) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).FailAutomationSimulation(ctx, &reason, org, id)
		return err
	})
}

type simulateWorker struct {
	river.WorkerDefaults[SimulateArgs]
	svc *Service
	log *slog.Logger
}

func (w *simulateWorker) Timeout(*river.Job[SimulateArgs]) time.Duration { return SimJobTimeout }

// Work runs the simulation; the last failed attempt marks it FAILED so no
// simulation is left running forever.
func (w *simulateWorker) Work(ctx context.Context, job *river.Job[SimulateArgs]) error {
	a := job.Args
	err := w.svc.RunSimulation(ctx, a.Org, a.Simulation)
	if err == nil || job.Attempt < job.MaxAttempts {
		return err
	}
	w.log.WarnContext(ctx, "automation.simulation_failed", slog.String("org", a.Org.String()),
		slog.String("simulation", a.Simulation.String()), pclog.Err(err))
	return w.svc.FailSimulation(context.WithoutCancel(ctx), a.Org, a.Simulation, "SIMULATION_FAILED")
}

// RegisterJobs adds the simulation worker.
func RegisterJobs(reg *jobs.Registry, svc *Service, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	return jobs.Register[SimulateArgs](reg, &simulateWorker{svc: svc, log: log})
}
