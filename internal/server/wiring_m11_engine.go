// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	approvalsapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/executionsrpc"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// The engine's ties to core (G0 M11 part 2 D9, D10, D57): issuance,
// revocation, runs, ceiling checks and voiding. Set by core's wiring; nil
// refuses the steps that need them (UNSUPPORTED_CAPABILITY) and skips the
// matching cleanup.
var (
	automationGrants        func(pool *db.Pool) steps.Grants
	automationRuns          func(pool *db.Pool) steps.Runs
	automationRevoker       func(pool *db.Pool) pgengine.GrantRevoker
	automationRunEnder      func(pool *db.Pool) pgengine.RunEnder
	automationCeilings      func(pool *db.Pool) autoports.CeilingChecker
	automationVoider        func(pool *db.Pool) pgengine.CeilingVoider
	automationSecuritySteps func(pool *db.Pool, d steps.Deps) autoports.StepRegistry
)

func init() {
	automationStarter = func(pool *db.Pool, bill *billing.Service, log *slog.Logger) autoports.Starter {
		return newAutomationEngine(engineDeps{pool: pool, bill: bill, log: log})
	}
	automationExecutions = func(pool *db.Pool) triggers.ExecutionLookup {
		return newAutomationEngine(engineDeps{pool: pool})
	}
}

// engineDeps are what the engine is built from; kp and publicURL enable
// webhook deliveries, notify personal notices.
type engineDeps struct {
	pool      *db.Pool
	bill      *billing.Service
	kp        keys.KeyProvider
	publicURL string
	notify    *napp.Service
	log       *slog.Logger
}

// newAutomationEngine builds the engine as pc_app (D24–D27): the generic
// and security steps over their ports, revalidation, cleanup and
// reconciliation.
func newAutomationEngine(d engineDeps) *pgengine.Engine {
	approvals := &approvalsapp.Service{Pool: d.pool}
	var notices steps.Notifier
	if d.notify != nil {
		approvals.Notify = d.notify
		notices = noticePort{n: d.notify}
	}
	deps := steps.Deps{
		Gates: gatesPort{svc: approvals}, Notifier: notices, Rollout: pgengine.Rollout{}, Recipients: pgengine.Recipients{},
	}
	if d.kp != nil {
		if del, err := automationDeliverer(d.pool, d.kp, d.bill, d.publicURL, d.log); err == nil {
			deps.Deliverer = del
		} else if d.log != nil {
			d.log.Warn("automation.deliverer_unavailable", slog.String("error", err.Error()))
		}
	}
	if automationGrants != nil {
		deps.Grants = automationGrants(d.pool)
	}
	if automationRuns != nil {
		deps.Runs = automationRuns(d.pool)
	}
	reg := steps.Generic(deps)
	if automationSecuritySteps != nil {
		for k, s := range automationSecuritySteps(d.pool, deps) {
			if _, taken := reg[k]; !taken {
				reg[k] = s
			}
		}
	}
	e, err := pgengine.New(d.pool, reg, d.log)
	if err != nil {
		panic(err) // the guard environment is a fixed, valid CEL environment
	}
	if d.pool != nil {
		if insert, err := jobs.NewClient(d.pool, nil, jobs.Config{Logger: d.log}); err == nil { // insert-only
			e.Client = insert
		}
	}
	e.Failures = &failures.Sink{}
	if d.bill != nil {
		e.Editions = d.bill
	}
	e.Reconciler = pgengine.Reconciliation{}
	cleanup := pgengine.Cleanup{Gates: approvals}
	if automationRevoker != nil {
		cleanup.Grants = automationRevoker(d.pool)
	}
	if automationRunEnder != nil {
		cleanup.Runs = automationRunEnder(d.pool)
	}
	e.Cleaner = cleanup
	if automationPauser != nil {
		e.Pauser = automationPauser(d.pool)
	}
	if automationCeilings != nil {
		e.Ceilings = automationCeilings(d.pool)
	}
	if automationVoider != nil {
		e.Voider = automationVoider(d.pool)
	}
	return e
}

// registerAutomationsEngine serves ExecutionService and
// AutomationLaunchService (G0 M11 part 2 D26, D28, D29); launches are
// authenticated by the workload's PAP/1 credentials.
func registerAutomationsEngine(rs *connect.Server, d apiDeps, workload *workloadrpc.Workload) {
	ed := engineDeps{pool: d.pool, bill: d.billing, kp: d.kp, publicURL: d.publicURL, log: d.log}
	if d.m5 != nil {
		ed.notify = d.m5.notifications
	}
	e := newAutomationEngine(ed)
	pantherclawv1connect.RegisterExecutionServiceHandler(rs, executionsrpc.New(e))
	pantherclawv1connect.RegisterAutomationLaunchServiceHandler(rs, workloadrpc.NewAutomationLaunches(workload, e))
}

// registerAutomationEngineJobs adds the driver and the wake sweep (D24).
func registerAutomationEngineJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, kp keys.KeyProvider,
	bill *billing.Service, publicURL string, notify *napp.Service, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	e := newAutomationEngine(engineDeps{pool: pool, bill: bill, kp: kp, publicURL: publicURL, notify: notify, log: log})
	p, err := pgengine.Register(reg, e)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

// gatesPort is steps.Gates over the approvals use cases (D25).
type gatesPort struct{ svc *approvalsapp.Service }

func (g gatesPort) gate(in steps.GateRequest) approvalsapp.AutomationGate {
	return approvalsapp.AutomationGate{
		Org: in.Org, Automation: in.Automation, AutomationName: in.AutomationName, ServiceAccount: in.ServiceAccount,
		Execution: in.Execution, StepID: in.StepID, Attempt: in.Attempt, ParamsDigest: in.ParamsDigest, Params: in.Params,
		Summary: in.Summary, Roles: in.Roles, Users: in.Users, Exclude: in.Exclude, MinApprovals: in.MinApprovals,
		Deadline: in.Deadline, Agent: in.Agent,
	}
}

func (g gatesPort) RequestGate(ctx context.Context, tx pgx.Tx, in steps.GateRequest) (ids.UUID, int, error) {
	return g.svc.RequestAutomationGateTx(ctx, tx, g.gate(in))
}

func (g gatesPort) EligibleGate(ctx context.Context, tx pgx.Tx, in steps.GateRequest) (int, error) {
	return g.svc.EligibleAutomationGateTx(ctx, tx, g.gate(in))
}

func (g gatesPort) GateStatus(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID) (steps.GateState, error) {
	st, err := g.svc.AutomationGateStateTx(ctx, tx, org, request)
	return steps.GateState{State: st.State, Approvers: st.Approvers}, err
}

func (g gatesPort) EndGate(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID, reason string) error {
	return g.svc.EndAutomationGateTx(ctx, tx, org, request, reason)
}

func (g gatesPort) ConsumeGate(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID) error {
	return g.svc.ConsumeAutomationGateTx(ctx, tx, org, request)
}

// noticePort is steps.Notifier over the notifications module (D25): the
// notice names the automation, the step and the execution only (HR-158);
// the message itself is read on the execution page.
type noticePort struct{ n *napp.Service }

func (p noticePort) Notify(ctx context.Context, tx pgx.Tx, n steps.Notice) (ids.UUID, error) {
	ttx, err := db.AdoptTenantTx(ctx, tx, n.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	a, err := dbq.New(ttx).GetAutomation(ctx, n.Org, n.Automation)
	if err != nil {
		return ids.UUID{}, err
	}
	typ := "automation.notice"
	if n.Shadow {
		typ = "automation.notice_shadow"
	}
	r, err := p.n.Enqueue(ctx, ttx, napp.Message{
		Org: n.Org, Type: typ, Personal: n.People, PersonalOnly: true,
		Params:    map[string]string{"automation": a.Name, "step": n.StepID, "execution": n.Execution.String()},
		Subject:   &napp.Subject{Type: "automation_execution", ID: n.Execution},
		DedupeKey: typ + ":" + n.Execution.String() + ":" + n.StepID,
	})
	return r.Notification, err
}
