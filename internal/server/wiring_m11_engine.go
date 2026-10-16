// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	approvalsapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/executionsrpc"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	"github.com/katocxl/pantherclaw/internal/billing"
	coverage "github.com/katocxl/pantherclaw/internal/coverage/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// automationSecuritySteps adds the templates stream's security steps
// (D31, D108); nil: none.
var automationSecuritySteps func(securityStepDeps) autoports.StepRegistry

// securityStepDeps is what the security steps are built from: the
// process's one core and the generic steps' ports, filled identically for
// the API and the driver (RoleAll and RoleWorker).
type securityStepDeps struct {
	Core      *automationsCore
	Pool      *db.Pool
	Bill      *billing.Service
	Log       *slog.Logger
	Steps     steps.Deps
	Notify    *napp.Service
	CEL       celenv.Limits
	Freshness coverage.Freshness
	LogOrigin string
}

func init() {
	automationStarter = func(core *automationsCore, pool *db.Pool, bill *billing.Service, log *slog.Logger) autoports.Starter {
		return newAutomationEngine(engineDeps{pool: pool, bill: bill, core: core, log: log})
	}
	automationExecutions = func(core *automationsCore, pool *db.Pool) triggers.ExecutionLookup {
		return newAutomationEngine(engineDeps{pool: pool, core: core})
	}
	automationPauser = func(core *automationsCore) autoports.Pauser { return core.svc }
	automationPackExecutions = func(core *automationsCore, pool *db.Pool) packbuild.Executions {
		return newAutomationEngine(engineDeps{pool: pool, core: core})
	}
}

// engineDeps are what the engine is built from; kp and publicURL enable
// webhook deliveries, notify personal notices; core is the process's one
// core (D91 K6, D105): the engine issues, revokes, runs, checks, pauses
// and voids only through it.
type engineDeps struct {
	pool      *db.Pool
	bill      *billing.Service
	kp        keys.KeyProvider
	publicURL string
	notify    *napp.Service
	core      *automationsCore
	log       *slog.Logger
	// cel, freshness and logOrigin come from the server config (D108a).
	cel       celenv.Limits
	freshness coverage.Freshness
	logOrigin string
}

// newAutomationEngine builds the engine as pc_app (D24–D27): the generic
// and security steps over their ports, revalidation through core,
// cleanup and reconciliation.
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
	var deliveries pgengine.DeliveryCanceler
	if d.kp != nil {
		if del, err := automationDeliverer(d.pool, d.kp, d.bill, d.publicURL, d.log, d.core); err == nil {
			deps.Deliverer = del
			if c, ok := del.(pgengine.DeliveryCanceler); ok {
				deliveries = c
			}
		} else if d.log != nil {
			d.log.Warn("automation.deliverer_unavailable", slog.String("error", err.Error()))
		}
	}
	cleanup := pgengine.Cleanup{Gates: approvals, Deliveries: deliveries}
	if d.core != nil {
		g, r := grantsPort{core: d.core}, runsPort{core: d.core}
		deps.Grants, deps.Runs = g, r
		cleanup.Grants, cleanup.Runs = g, r
	}
	reg := steps.Generic(deps)
	if automationSecuritySteps != nil {
		for k, s := range automationSecuritySteps(securityStepDeps{
			Core: d.core, Pool: d.pool, Bill: d.bill, Log: d.log, Steps: deps, Notify: d.notify, CEL: d.cel,
			Freshness: d.freshness, LogOrigin: d.logOrigin,
		}) {
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
	e.Cleaner = cleanup
	if d.core != nil {
		e.Pauser, e.Ceilings, e.Voider = d.core.svc, d.core.svc, d.core.svc
	}
	probeM11("automations.engine", e)
	return e
}

// registerAutomationsEngine serves ExecutionService and
// AutomationLaunchService (G0 M11 part 2 D26, D28, D29); launches are
// authenticated by the workload's PAP/1 credentials. Core's controls cancel
// executions through the engine (D28).
func registerAutomationsEngine(rs *connect.Server, d apiDeps, workload *workloadrpc.Workload, core *automationsCore) {
	ed := engineDeps{
		pool: d.pool, bill: d.billing, kp: d.kp, publicURL: d.publicURL, core: core, log: d.log, cel: d.cel,
		freshness: d.freshness, logOrigin: d.logOrigin,
	}
	if d.m5 != nil {
		ed.notify = d.m5.notifications
	}
	e := newAutomationEngine(ed)
	shareCore(core, e, d.pool, d.billing, d.log)
	pantherclawv1connect.RegisterExecutionServiceHandler(rs, executionsrpc.New(e))
	pantherclawv1connect.RegisterAutomationLaunchServiceHandler(rs, workloadrpc.NewAutomationLaunches(workload, e))
}

// shareCore sets the engine, triggers and destinations ports on the one
// shared core instance (D96, K6).
func shareCore(core *automationsCore, e *pgengine.Engine, pool *db.Pool, bill *billing.Service, log *slog.Logger) {
	if core == nil || core.svc == nil {
		return
	}
	core.svc.Executions = executionsPort{e: e}
	core.svc.Triggers = automationTriggerActivator(pool, bill, log, core)
	core.svc.Destinations = endpoints.DestinationChecker{}
}

// registerAutomationEngineJobs adds the driver and the wake sweep (D24) on
// the process's one core, and attaches the engine's ports to it (a
// worker-only process too, D105).
func registerAutomationEngineJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, core *automationsCore, cfg *Config,
	kp keys.KeyProvider, bill *billing.Service, notify *napp.Service, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	e := driverEngine(core, engineDeps{
		bill: bill, kp: kp, publicURL: cfg.Auth.PublicURL, notify: notify, log: log, cel: cfg.CEL,
		freshness: freshnessOf(cfg), logOrigin: cfg.logOrigin(),
	})
	probeM11("automations.engine.driver", e)
	p, err := pgengine.Register(reg, e)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

// driverEngine is the engine the River driver runs every step with: it
// shares the process's core, whose grants and runs services are attached
// by the API or the core jobs.
func driverEngine(core *automationsCore, d engineDeps) *pgengine.Engine {
	d.pool, d.core = core.svc.Pool, core
	e := newAutomationEngine(d)
	shareCore(core, e, d.pool, d.bill, d.log)
	return e
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
	typ := "automation.notice"
	if n.Shadow {
		typ = "automation.notice_shadow"
	}
	r, err := p.n.Enqueue(ctx, ttx, napp.Message{
		Org: n.Org, Type: typ, Personal: n.People, PersonalOnly: true,
		Params:    map[string]string{"automation": n.Automation.String(), "step": n.StepID, "execution": n.Execution.String()},
		Subject:   &napp.Subject{Type: "automation_execution", ID: n.Execution},
		DedupeKey: typ + ":" + n.Execution.String() + ":" + n.StepID,
	})
	return r.Notification, err
}

// grantsPort is steps.Grants and the cleanup's GrantRevoker over the
// shared core's grants service (D9), read at each call: a worker-only
// process attaches it after the engine is built.
type grantsPort struct{ core *automationsCore }

func (g grantsPort) svc() (*grantsapp.Service, error) {
	if g.core.grants == nil {
		return nil, errCoreDetached
	}
	return g.core.grants, nil
}

// errCoreDetached: the shared core has no grants or runs service yet.
var errCoreDetached = errors.New("automations: the core has no grants or runs service attached")

func (g grantsPort) IssueForAutomation(ctx context.Context, tx pgx.Tx, in steps.LaunchIssue) (ids.UUID, error) {
	svc, err := g.svc()
	if err != nil {
		return ids.UUID{}, err
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, in.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	gr, err := svc.IssueForAutomationTx(ctx, ttx, grantsapp.AutomationIssue{
		Org: in.Org, Automation: in.Automation, Version: in.Version, Execution: in.Execution, Trigger: in.Trigger,
		Ceiling: in.Ceiling, ServiceAccount: in.ServiceAccount, AgentID: in.Agent, InstanceID: in.Instance,
		Principal: in.Principal, TaskRef: in.TaskRef, TTL: in.TTL, Bounds: in.Bounds, Requirements: in.Requirements,
		Limits: in.Limits, Live: in.Live, DryRun: in.DryRun,
	})
	if err != nil {
		return ids.UUID{}, err
	}
	return gr.ID.UUID(), nil
}

func (g grantsPort) RevokeForAutomation(ctx context.Context, tx pgx.Tx, in steps.GrantRevoke) ([]ids.UUID, error) {
	svc, err := g.svc()
	if err != nil {
		return nil, err
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, in.Org)
	if err != nil {
		return nil, err
	}
	r := grantsapp.AutomationRevoke{
		Org: in.Org, Automation: in.Automation, Execution: in.Execution, Trigger: in.Trigger, Ceiling: in.Ceiling,
		ServiceAccount: in.ServiceAccount, Agents: in.Agents, Revocable: in.Revocable, RevocableAll: in.RevocableAll,
		Scope: in.Scope, Reason: in.Reason,
	}
	if in.Grant != nil {
		r.Grant = *in.Grant
	}
	revoked, err := svc.RevokeForAutomationTx(ctx, ttx, r)
	out := make([]ids.UUID, 0, len(revoked))
	for _, id := range revoked {
		out = append(out, id.UUID())
	}
	return out, err
}

// RevokeExecutionGrants implements pgengine.GrantRevoker (cleanup, D24).
func (g grantsPort) RevokeExecutionGrants(ctx context.Context, tx pgx.Tx, x *engine.Exec, reason string) ([]ids.UUID, error) {
	return g.RevokeForAutomation(ctx, tx, steps.GrantRevoke{
		Org: x.Org, Automation: x.Automation, Execution: x.ID, Trigger: x.View.Trigger.ID, Ceiling: x.View.Ceiling,
		ServiceAccount: x.View.ServiceAccount, Scope: grantsapp.RevokeScopeExecution, Reason: reason,
	})
}

// runsPort is steps.Runs and the cleanup's RunEnder over the shared
// core's runs service (D10), read at each call.
type runsPort struct{ core *automationsCore }

func (r runsPort) svc() (*runsapp.Service, error) {
	if r.core.runs == nil {
		return nil, errCoreDetached
	}
	return r.core.runs, nil
}

func (r runsPort) StartForAutomation(ctx context.Context, tx pgx.Tx, in steps.LaunchStart) (ids.UUID, error) {
	svc, err := r.svc()
	if err != nil {
		return ids.UUID{}, err
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, in.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	run, err := svc.StartForAutomationTx(ctx, ttx, runsapp.AutomationStart{
		Org: in.Org, Automation: in.Automation, Version: in.Version, Execution: in.Execution, Trigger: in.Trigger,
		ServiceAccount: in.ServiceAccount, AgentID: in.Agent, InstanceID: in.Instance, GrantID: in.Grant,
		Principal: in.Principal, TaskRef: in.TaskRef, TTL: in.TTL, DryRun: in.DryRun,
	})
	return run.ID, err
}

func (r runsPort) EndForAutomation(ctx context.Context, tx pgx.Tx, org ids.OrgID, execution, serviceAccount, run ids.UUID,
	reason string,
) error {
	svc, err := r.svc()
	if err != nil {
		return err
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return err
	}
	_, err = svc.EndForAutomationTx(ctx, ttx, org, execution, serviceAccount, run, reason)
	return err
}

// EndExecutionRuns implements pgengine.RunEnder (cleanup, D24): every
// active run of the execution ends.
func (r runsPort) EndExecutionRuns(ctx context.Context, tx pgx.Tx, x *engine.Exec, reason string) ([]ids.UUID, error) {
	svc, err := r.svc()
	if err != nil {
		return nil, err
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, x.Org)
	if err != nil {
		return nil, err
	}
	runs, err := dbq.New(ttx).ExecutionRuns(ctx, x.Org, &x.ID)
	if err != nil {
		return nil, err
	}
	reason = steps.CutUTF8(reason, 64)
	var out []ids.UUID
	for _, run := range runs {
		if run.EffectiveState != "ACTIVE" {
			continue
		}
		if _, err := svc.EndForAutomationTx(ctx, ttx, x.Org, x.ID, x.View.ServiceAccount, run.ID, reason); err != nil {
			return nil, err
		}
		out = append(out, run.ID)
	}
	return out, nil
}

// executionsPort is core's Executions over the engine (D28): pause with
// cancel_active, retirement and RevokeAuthority cancel in their own
// transaction.
type executionsPort struct{ e *pgengine.Engine }

func (p executionsPort) CancelActive(ctx context.Context, tx pgx.Tx, org ids.OrgID, automation ids.UUID, reason string,
) (autoapp.ControlEffect, error) {
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return autoapp.ControlEffect{}, err
	}
	by, actor := "system", evdomain.Actor{Type: "system", ID: "automations"}
	if c, err := tenancy.CallerFrom(ctx); err == nil {
		by, actor = c.Principal.String(), c.Actor()
	}
	eff, err := p.e.CancelAutomationTx(ctx, ttx, automation, by, reason, actor, "")
	return autoapp.ControlEffect{
		GrantsRevoked: eff.Grants, RunsEnded: eff.Runs, LaunchesCancelled: eff.Launches,
		DeliveriesCancelled: eff.Deliveries, DeliveriesNotVerified: eff.DeliveriesNotVerified, ExecutionsAffected: eff.Executions,
	}, err
}

// automationPackExecutions reads executions for evidence packs of scope
// automation_execution (D30); set by init.
var automationPackExecutions func(core *automationsCore, pool *db.Pool) packbuild.Executions
