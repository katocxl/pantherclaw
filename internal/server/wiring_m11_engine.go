// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"sync"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	approvalsapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/executionsrpc"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	"github.com/katocxl/pantherclaw/internal/billing"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// automationSecuritySteps adds the templates stream's security steps
// (D31); nil: none.
var automationSecuritySteps func(pool *db.Pool, d steps.Deps) autoports.StepRegistry

func init() {
	automationStarter = func(pool *db.Pool, bill *billing.Service, log *slog.Logger) autoports.Starter {
		return newAutomationEngine(engineDeps{pool: pool, bill: bill, log: log})
	}
	automationExecutions = func(pool *db.Pool) triggers.ExecutionLookup {
		return newAutomationEngine(engineDeps{pool: pool})
	}
	automationPauser = func(pool *db.Pool) autoports.Pauser { return &lazyPauser{pool: pool} }
	automationPackExecutions = func(pool *db.Pool) packbuild.Executions {
		return newAutomationEngine(engineDeps{pool: pool})
	}
}

// engineDeps are what the engine is built from; kp and publicURL enable
// webhook deliveries, notify personal notices, core the API's own core
// services (else the engine builds its own).
type engineDeps struct {
	pool      *db.Pool
	bill      *billing.Service
	kp        keys.KeyProvider
	publicURL string
	notify    *napp.Service
	core      *automationsCore
	log       *slog.Logger
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
	core := engineCore(d.pool, d.bill, d.core)
	deps := steps.Deps{
		Gates: gatesPort{svc: approvals}, Notifier: notices, Rollout: pgengine.Rollout{}, Recipients: pgengine.Recipients{},
	}
	var deliveries pgengine.DeliveryCanceler
	if d.kp != nil {
		if del, err := automationDeliverer(d.pool, d.kp, d.bill, d.publicURL, d.log); err == nil {
			deps.Deliverer = del
			if c, ok := del.(pgengine.DeliveryCanceler); ok {
				deliveries = c
			}
		} else if d.log != nil {
			d.log.Warn("automation.deliverer_unavailable", slog.String("error", err.Error()))
		}
	}
	cleanup := pgengine.Cleanup{Gates: approvals, Deliveries: deliveries}
	if core != nil && core.grants != nil && core.runs != nil {
		g, r := grantsPort{svc: core.grants}, runsPort{svc: core.runs}
		deps.Grants, deps.Runs = g, r
		cleanup.Grants, cleanup.Runs = g, r
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
	e.Cleaner = cleanup
	if core != nil {
		e.Pauser, e.Ceilings, e.Voider = core.svc, core.svc, core.svc
	}
	probeM11("automations.engine", e)
	return e
}

// registerAutomationsEngine serves ExecutionService and
// AutomationLaunchService (G0 M11 part 2 D26, D28, D29); launches are
// authenticated by the workload's PAP/1 credentials. Core's controls cancel
// executions through the engine (D28).
func registerAutomationsEngine(rs *connect.Server, d apiDeps, workload *workloadrpc.Workload, core *automationsCore) {
	ed := engineDeps{pool: d.pool, bill: d.billing, kp: d.kp, publicURL: d.publicURL, core: core, log: d.log}
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
	core.svc.Triggers = automationTriggerActivator(pool, bill, log)
	core.svc.Destinations = endpoints.DestinationChecker{}
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

// engineCore is the core the engine issues, revokes, runs, checks and
// voids through (G0 M11 part 2 D9, D10, D57): the API's own services, or a
// fresh set for the workers.
func engineCore(pool *db.Pool, bill *billing.Service, core *automationsCore) *automationsCore {
	if core != nil || pool == nil {
		return core
	}
	gstore := &grantspg.Store{Pool: pool}
	grants := &grantsapp.Service{
		Repo: gstore, Subjects: gstore, Defs: &defspg.Store{Pool: pool}, Authz: grantsapp.SubjectAuthorizer{},
		Clock: clock.System{}, Store: gstore,
	}
	return newAutomationsCore(pool, bill, "", grants, runsapp.New(pool).WithGrants(gstore))
}

// grantsPort is steps.Grants and the cleanup's GrantRevoker over core's
// grants service (D9).
type grantsPort struct{ svc *grantsapp.Service }

func (g grantsPort) IssueForAutomation(ctx context.Context, tx pgx.Tx, in steps.LaunchIssue) (ids.UUID, error) {
	ttx, err := db.AdoptTenantTx(ctx, tx, in.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	gr, err := g.svc.IssueForAutomationTx(ctx, ttx, grantsapp.AutomationIssue{
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
	revoked, err := g.svc.RevokeForAutomationTx(ctx, ttx, r)
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

// runsPort is steps.Runs and the cleanup's RunEnder over core's runs
// service (D10).
type runsPort struct{ svc *runsapp.Service }

func (r runsPort) StartForAutomation(ctx context.Context, tx pgx.Tx, in steps.LaunchStart) (ids.UUID, error) {
	ttx, err := db.AdoptTenantTx(ctx, tx, in.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	run, err := r.svc.StartForAutomationTx(ctx, ttx, runsapp.AutomationStart{
		Org: in.Org, Automation: in.Automation, Version: in.Version, Execution: in.Execution, Trigger: in.Trigger,
		ServiceAccount: in.ServiceAccount, AgentID: in.Agent, InstanceID: in.Instance, GrantID: in.Grant,
		Principal: in.Principal, TaskRef: in.TaskRef, TTL: in.TTL, DryRun: in.DryRun,
	})
	return run.ID, err
}

func (r runsPort) EndForAutomation(ctx context.Context, tx pgx.Tx, org ids.OrgID, execution, serviceAccount, run ids.UUID,
	reason string,
) error {
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return err
	}
	_, err = r.svc.EndForAutomationTx(ctx, ttx, org, execution, serviceAccount, run, reason)
	return err
}

// EndExecutionRuns implements pgengine.RunEnder (cleanup, D24): every
// active run of the execution ends.
func (r runsPort) EndExecutionRuns(ctx context.Context, tx pgx.Tx, x *engine.Exec, reason string) ([]ids.UUID, error) {
	ttx, err := db.AdoptTenantTx(ctx, tx, x.Org)
	if err != nil {
		return nil, err
	}
	runs, err := dbq.New(ttx).ExecutionRuns(ctx, x.Org, &x.ID)
	if err != nil {
		return nil, err
	}
	if len(reason) > 64 {
		reason = reason[:64]
	}
	var out []ids.UUID
	for _, run := range runs {
		if run.EffectiveState != "ACTIVE" {
			continue
		}
		if _, err := r.svc.EndForAutomationTx(ctx, ttx, x.Org, x.ID, x.View.ServiceAccount, run.ID, reason); err != nil {
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
		DeliveriesCancelled: eff.Deliveries, ExecutionsAffected: eff.Executions,
	}, err
}

// automationPackExecutions reads executions for evidence packs of scope
// automation_execution (D30); set by init.
var automationPackExecutions func(pool *db.Pool) packbuild.Executions

// lazyPauser is the Pauser triggers call (core's pause, D14): core is built
// on first use, with triggers' activator, so building triggers never
// builds core again.
type lazyPauser struct {
	pool *db.Pool
	once sync.Once
	svc  *autoapp.Service
}

// Pause implements autoports.Pauser.
func (p *lazyPauser) Pause(ctx context.Context, tx pgx.Tx, org ids.OrgID, sel autodomain.PauseSelector, reason autodomain.PauseReason,
) ([]ids.UUID, error) {
	p.once.Do(func() {
		p.svc = engineCore(p.pool, nil, nil).svc
		p.svc.Triggers = automationTriggerActivator(p.pool, nil, nil)
	})
	return p.svc.Pause(ctx, tx, org, sel, reason)
}
