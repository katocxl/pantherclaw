// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/jackc/pgx/v5"

	approvalsapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/inbound"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/keystore"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/promotions"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// autoStack is the M11 governed-automations exit scenario's in-process
// Business half (G0 M11 part 2 D49, D96, D117): the real automations core,
// change ceremony, grants and runs (with govern's promotion gate), the
// engine, triggers, the inbound receiver, assurance and the launch
// service, on the e2e stack's database, with an edition fake.
//
// Why the engine has no job client: the e2e server is Community and shares
// the database and its River queue. Its engine driver and wake sweep would
// pick up an in-process LIVE execution and fail it (no Automations
// entitlement), so this engine enqueues nothing, the test advances each
// execution itself, and every execution is parked (wake_at an hour ahead)
// from its start and between steps.
//
// Scope: this e2e drives the scenario's generic kinds (launch_run,
// wait_run, wait_effect) through adapters copied from the server's wiring;
// the server's own adapters and the deliver, notify and security-step kinds
// are outside it, covered by TestM11_WiringComplete and the streams' tests
// (D120 E2).
type autoStack struct {
	r        *reflexStack
	ents     ents
	core     *autoapp.Service
	changes  *changes.Service
	grants   *grantsapp.Service
	runs     *runsapp.Service
	engine   *pgengine.Engine
	triggers *triggers.Service
	sources  *endpoints.Service
	asr      *assurance.Service
	// receiver serves the inbound events endpoint; launches serves
	// WorkloadService and AutomationLaunchService in-process and forwards
	// every other request to the real server.
	receiver, launches *httptest.Server
}

func startAutomations(t *testing.T, r *reflexStack) *autoStack {
	t.Helper()
	s, pool := r.s, r.s.pool
	a := &autoStack{r: r, ents: ents{billing.Business}}
	log := pclog.Discard()
	a.changes = changes.New(pool, s.apiURL)
	a.core = &autoapp.Service{
		Pool: pool, Clock: clock.System{}, Changes: a.changes, Operations: &defspg.Store{Pool: pool},
		Failures: &failures.Sink{}, Editions: a.ents, TestGate: assurance.TestGate{}, Rollout: assurance.RolloutEvidence{},
	}
	a.core.RegisterChanges()
	// Grants and runs as the server builds them (newGrants, attach).
	gate := promotions.Gate{Packages: &defspg.Store{Pool: pool}}
	gstore := &grantspg.Store{Pool: pool, Promotions: gate}
	a.grants = &grantsapp.Service{
		Repo: gstore, Subjects: gstore, Defs: &defspg.Store{Pool: pool}, Authz: grantsapp.SubjectAuthorizer{},
		Clock: clock.System{}, Listing: gstore, Refusals: gstore, Store: gstore, Promotions: gate,
	}
	a.runs = runsapp.New(pool).WithGrants(gstore)
	a.grants.Ceilings = a.core
	a.runs.WithAutomationRuns(a.core)
	a.core.Grants, a.core.Runs = a.grants, a.runs

	// The engine (newAutomationEngine), without a job client.
	approvals := &approvalsapp.Service{Pool: pool}
	g, rn := e2eGrants{svc: a.grants}, e2eRuns{svc: a.runs}
	e, err := pgengine.New(pool, steps.Generic(steps.Deps{
		Grants: g, Runs: rn, Gates: e2eGates{svc: approvals}, Rollout: pgengine.Rollout{}, Recipients: pgengine.Recipients{},
	}), log)
	if err != nil {
		t.Fatal(err)
	}
	e.Failures, e.Editions, e.Reconciler = &failures.Sink{}, a.ents, pgengine.Reconciliation{}
	e.Cleaner = pgengine.Cleanup{Grants: g, Runs: rn, Gates: approvals}
	e.Pauser, e.Ceilings, e.Voider = a.core, a.core, a.core
	a.engine = e
	a.core.Executions = e2eExecutions{e: e}

	a.triggers = triggers.New(triggers.Deps{
		Pool: pool, Starter: parkingStarter{e: e}, Pauser: a.core, Executions: e, Editions: a.ents, Failures: &failures.Sink{},
		Raiser: (&reflexapp.Hooks{Ents: a.ents}).Raiser(), Clock: clock.System{}, Log: log,
	})
	a.core.Triggers = a.triggers.Activator()
	a.core.Destinations = endpoints.DestinationChecker{}

	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.receiver = httptest.NewServer(mux)
	t.Cleanup(a.receiver.Close)
	a.sources, err = endpoints.New(pool, pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp)), a.triggers, a.ents,
		endpoints.Config{PublicURL: a.receiver.URL}, clock.System{}, log)
	if err != nil {
		t.Fatal(err)
	}
	a.sources.WithFailures(&failures.Sink{})
	a.sources.Receiver().Mount(mux)

	a.asr = &assurance.Service{Pool: pool, Ents: a.ents, Issuer: a.grants}

	// The launch service and workload tokens, as the workload API serves
	// them: the real server's keys and issuer, so the gateway accepts the
	// tokens; PAP/1 proofs name this URL.
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(context.Background(), pool, kp, reg); err != nil {
		t.Fatal(err)
	}
	identity := iapp.New(pool, reg, s.apiURL, clock.System{})
	upstream, err := url.Parse(s.apiURL)
	if err != nil {
		t.Fatal(err)
	}
	lmux := http.NewServeMux()
	lmux.Handle("/", httputil.NewSingleHostReverseProxy(upstream))
	a.launches = httptest.NewUnstartedServer(nil)
	cs := connect.NewServer()
	w := workloadrpc.NewWorkload(identity, a.runs, "http://"+a.launches.Listener.Addr().String(), clock.System{}).WithGrants(a.grants)
	pantherclawv1connect.RegisterWorkloadServiceHandler(cs, w)
	pantherclawv1connect.RegisterAutomationLaunchServiceHandler(cs, workloadrpc.NewAutomationLaunches(w, e))
	connecthttp.Mount(lmux, cs)
	a.launches.Config.Handler = workloadrpc.RawBody(lmux, nil)
	a.launches.Start()
	t.Cleanup(a.launches.Close)
	return a
}

// signedEvent posts an inbound event to the receiver, signed with the
// source's whsec_ secret (Standard Webhooks), and returns the status.
func (a *autoStack) signedEvent(t *testing.T, source ids.UUID, secret, msgID, body string) int {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, a.receiver.URL+"/v1/automations/events/"+a.r.s.org.String()+"/"+source.String(),
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(inbound.HeaderID, msgID)
	req.Header.Set(inbound.HeaderTimestamp, strconv.FormatInt(now.Unix(), 10))
	req.Header.Set(inbound.HeaderSignature, ndomain.Sign(key, msgID, now.Unix(), []byte(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// parkingStarter starts executions on the in-process engine and parks each
// new row an hour ahead in the same transaction (D120 E1): a new execution
// is due at once (wake_at NULL), so the e2e server's sweep could otherwise
// take it before the test advances it.
type parkingStarter struct{ e *pgengine.Engine }

func (p parkingStarter) Start(ctx context.Context, tx pgx.Tx, ref autodomain.TriggerRef) (ids.UUID, error) {
	id, err := p.e.Start(ctx, tx, ref)
	if err != nil {
		return id, err
	}
	_, err = tx.Exec(ctx, "UPDATE pc.automation_executions SET wake_at = now() + interval '1 hour' WHERE id = $1", id)
	return id, err
}

// advance runs an execution's ready steps now, then parks it an hour ahead
// so the e2e server's sweep leaves it alone.
func (a *autoStack) advance(t *testing.T, id ids.UUID) {
	t.Helper()
	s := a.r.s
	s.exec(t, "UPDATE pc.automation_executions SET wake_at = now() - interval '1 second' WHERE id = $1 AND wake_at IS NOT NULL", id)
	s.exec(t, "UPDATE pc.automation_step_attempts SET wake_at = now() - interval '1 second' WHERE execution_id = $1 AND wake_at IS NOT NULL", id)
	if err := a.engine.Advance(context.Background(), s.org, id); err != nil {
		t.Fatalf("advance %s: %v", id, err)
	}
	s.exec(t, `UPDATE pc.automation_executions SET wake_at = now() + interval '1 hour'
		WHERE id = $1 AND state IN ('PENDING', 'RUNNING', 'WAITING', 'NEEDS_RECONCILIATION')`, id)
}

// The engine's ports over the in-process grants, runs and approvals, as
// the server adapts them (wiring_m11_engine.go grantsPort, runsPort,
// gatesPort, executionsPort).

type e2eGrants struct{ svc *grantsapp.Service }

func (g e2eGrants) IssueForAutomation(ctx context.Context, tx pgx.Tx, in steps.LaunchIssue) (ids.UUID, error) {
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

func (g e2eGrants) RevokeForAutomation(ctx context.Context, tx pgx.Tx, in steps.GrantRevoke) ([]ids.UUID, error) {
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

func (g e2eGrants) RevokeExecutionGrants(ctx context.Context, tx pgx.Tx, x *engine.Exec, reason string) ([]ids.UUID, error) {
	return g.RevokeForAutomation(ctx, tx, steps.GrantRevoke{
		Org: x.Org, Automation: x.Automation, Execution: x.ID, Trigger: x.View.Trigger.ID, Ceiling: x.View.Ceiling,
		ServiceAccount: x.View.ServiceAccount, Scope: grantsapp.RevokeScopeExecution, Reason: reason,
	})
}

type e2eRuns struct{ svc *runsapp.Service }

func (r e2eRuns) StartForAutomation(ctx context.Context, tx pgx.Tx, in steps.LaunchStart) (ids.UUID, error) {
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

func (r e2eRuns) EndForAutomation(ctx context.Context, tx pgx.Tx, org ids.OrgID, execution, serviceAccount, run ids.UUID,
	reason string,
) error {
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return err
	}
	_, err = r.svc.EndForAutomationTx(ctx, ttx, org, execution, serviceAccount, run, reason)
	return err
}

func (r e2eRuns) EndExecutionRuns(ctx context.Context, tx pgx.Tx, x *engine.Exec, reason string) ([]ids.UUID, error) {
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
		if _, err := r.svc.EndForAutomationTx(ctx, ttx, x.Org, x.ID, x.View.ServiceAccount, run.ID, reason); err != nil {
			return nil, err
		}
		out = append(out, run.ID)
	}
	return out, nil
}

type e2eGates struct{ svc *approvalsapp.Service }

func (g e2eGates) gate(in steps.GateRequest) approvalsapp.AutomationGate {
	return approvalsapp.AutomationGate{
		Org: in.Org, Automation: in.Automation, AutomationName: in.AutomationName, ServiceAccount: in.ServiceAccount,
		Execution: in.Execution, StepID: in.StepID, Attempt: in.Attempt, ParamsDigest: in.ParamsDigest, Params: in.Params,
		Summary: in.Summary, Roles: in.Roles, Users: in.Users, Exclude: in.Exclude, MinApprovals: in.MinApprovals,
		Deadline: in.Deadline, Agent: in.Agent,
	}
}

func (g e2eGates) RequestGate(ctx context.Context, tx pgx.Tx, in steps.GateRequest) (ids.UUID, int, error) {
	return g.svc.RequestAutomationGateTx(ctx, tx, g.gate(in))
}

func (g e2eGates) EligibleGate(ctx context.Context, tx pgx.Tx, in steps.GateRequest) (int, error) {
	return g.svc.EligibleAutomationGateTx(ctx, tx, g.gate(in))
}

func (g e2eGates) GateStatus(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID) (steps.GateState, error) {
	st, err := g.svc.AutomationGateStateTx(ctx, tx, org, request)
	return steps.GateState{State: st.State, Approvers: st.Approvers}, err
}

func (g e2eGates) EndGate(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID, reason string) error {
	return g.svc.EndAutomationGateTx(ctx, tx, org, request, reason)
}

func (g e2eGates) ConsumeGate(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID) error {
	return g.svc.ConsumeAutomationGateTx(ctx, tx, org, request)
}

type e2eExecutions struct{ e *pgengine.Engine }

func (p e2eExecutions) CancelActive(ctx context.Context, tx pgx.Tx, org ids.OrgID, automation ids.UUID, reason string,
) (autoapp.ControlEffect, error) {
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return autoapp.ControlEffect{}, err
	}
	by, actor := "system", evdomain.Actor{Type: "system", ID: "automations"}
	if c, err := tapp.CallerFrom(ctx); err == nil {
		by, actor = c.Principal.String(), c.Actor()
	}
	eff, err := p.e.CancelAutomationTx(ctx, ttx, automation, by, reason, actor, "")
	return autoapp.ControlEffect{
		GrantsRevoked: eff.Grants, RunsEnded: eff.Runs, LaunchesCancelled: eff.Launches,
		DeliveriesCancelled: eff.Deliveries, DeliveriesNotVerified: eff.DeliveriesNotVerified, ExecutionsAffected: eff.Executions,
	}, err
}
