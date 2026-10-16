// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgengine_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	approvalsapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// efx is an org with an agent, an enabled automation with an ACTIVE
// ceiling, and an engine whose grant and run ports write real rows.
type efx struct {
	*triggerstest.Fixture
	t          *testing.T
	agent, env ids.UUID
	auto       triggerstest.Automation
	ceiling    ids.UUID
	e          *pgengine.Engine
	grants     *fakeGrants
	approvals  *approvalsapp.Service
}

const launchSteps = `"do":[
	{"id":"launch","step":"launch_run","with":{"agent":"AGENT"}},
	{"id":"wait","step":"wait_run","with":{"step":"launch"},"timeout":"2h"}],
	"finish_when":[{"step":"wait","condition":"RUN_ENDED"}]`

const gateSteps = `"do":[
	{"id":"approve","step":"gate","with":{"approvers":{"roles":["automation_operator"]},"deadline":"1h","summary":"refund {{params.ticket}}"}}],
	"finish_when":[]`

func definition(agent ids.UUID, body string) string {
	return `{"apiVersion":"` + autodomain.APIVersion + `","kind":"Automation","purpose":"test","work_kind":"AGENT_WORK",
		"review_by":"` + time.Now().AddDate(0, 0, 30).Format(time.DateOnly) + `",
		"when":{"manual":{"params":{"ticket":{"type":"string","pattern":"T-[0-9]+"}}}},
		"authority":{"principal":"self","ceiling":{"agents":["` + agent.String() + `"],
			"bounds":{"operations":["payments.refund"]},"per_grant":{"ttl":"1h"},"per_day":{"grants":5,"runs":5},"concurrency":2}},` +
		strings.ReplaceAll(body, "AGENT", agent.String()) + `}`
}

func newEfx(t *testing.T, body string) *efx {
	t.Helper()
	f := &efx{Fixture: triggerstest.New(t), t: t, agent: ids.NewV7(), env: ids.NewV7(), ceiling: ids.NewV7()}
	f.Exec(t, "INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'dev', 'Dev', 'DEVELOPMENT')", f.Org, f.env)
	f.Exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'refunder', 'DISCOVERED', 'test')", f.Org, f.agent)
	f.auto = f.Automation(t, "refunds", definition(f.agent, body), autodomain.RolloutFull)
	request := ids.NewV7()
	f.Exec(t, `INSERT INTO pc.change_requests (org_id, id, domain, kind, subject_id, content_digest, binding, summary, required,
		requested_by, expires_at) VALUES ($1, $2, 'automation', 'ENABLE', $3, $4, $4, '{}', 1, 'user:test', now() + interval '1 hour')`,
		f.Org, request, f.auto.ID, bytes.Repeat([]byte{7}, 32))
	f.Exec(t, `INSERT INTO pc.automation_ceilings (org_id, id, automation_id, version_id, digest, approved_by, change_request_id,
		review_by) VALUES ($1, $2, $3, $4, $5, ARRAY[$6::uuid], $7, now() + interval '30 days')`,
		f.Org, f.ceiling, f.auto.ID, f.auto.Version, bytes.Repeat([]byte{8}, 32), f.User, request)
	f.grants = &fakeGrants{f: f}
	f.approvals = &approvalsapp.Service{Pool: f.Pool}
	reg := steps.Generic(steps.Deps{
		Grants: f.grants, Runs: fakeRuns{f: f}, Gates: gates{f.approvals}, Rollout: pgengine.Rollout{},
		Recipients: pgengine.Recipients{},
	})
	e, err := pgengine.New(f.Pool, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Cleaner = pgengine.Cleanup{Grants: f.grants, Runs: fakeRuns{f: f}, Gates: f.approvals}
	e.Reconciler = pgengine.Reconciliation{}
	f.e = e
	return f
}

// start records a manual trigger with ticket and starts its execution.
func (f *efx) start(ticket string) ids.UUID {
	f.t.Helper()
	trig := ids.NewV7()
	var exec ids.UUID
	f.Tx(f.t, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO pc.automation_triggers (org_id, id, automation_id, version_id, kind, mode, source_ref,
			authenticity, params, root_trigger_id, state, occurred_at) VALUES ($1, $2, $3, $4, 'MANUAL', 'LIVE', 'manual:test',
			'USER_SESSION', '{}', $2, 'ACCEPTED', now())`, f.Org, trig, f.auto.ID, f.auto.Version); err != nil {
			return err
		}
		var err error
		exec, err = f.e.Start(ctx, tx.Pgx(), autodomain.TriggerRef{
			ID: trig, Org: f.Org, Automation: f.auto.ID, Version: f.auto.Version, Kind: autodomain.TriggerManual,
			Mode: autodomain.ModeLive, Root: trig, OccurredAt: time.Now(),
			Params: map[string]autodomain.Value{"ticket": {Type: autodomain.ParamString, String: ticket}},
		})
		return err
	})
	return exec
}

// advance works the execution once, waking its waits first.
func (f *efx) advance(exec ids.UUID) {
	f.t.Helper()
	f.Exec(f.t, `UPDATE pc.automation_step_attempts SET wake_at = now() - interval '1 second'
		WHERE org_id = $1 AND execution_id = $2 AND state IN ('RUNNING', 'WAITING')`, f.Org, exec)
	if err := f.e.Advance(context.Background(), f.Org, exec); err != nil {
		f.t.Fatal(err)
	}
}

func (f *efx) str(sql string, args ...any) string {
	f.t.Helper()
	var s string
	f.Tx(f.t, func(ctx context.Context, tx db.TenantTx) error { return tx.QueryRow(ctx, sql, args...).Scan(&s) })
	return s
}

func (f *efx) manager() context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: f.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.User},
			Bindings: []td.Binding{{Role: td.RoleAutomationAuthor, Scope: td.Scope{Type: td.ScopeOrg, ID: f.Org.UUID()}}},
		},
		Credential: tenancy.CredBrowserSession,
	})
}

// fakeGrants writes a service-account grant under the ceiling, as core's
// issuance does after its checks, and revokes by marking rows.
type fakeGrants struct {
	f       *efx
	revoked []ids.UUID
}

func (g *fakeGrants) IssueForAutomation(ctx context.Context, tx pgx.Tx, in steps.LaunchIssue) (ids.UUID, error) {
	id := ids.NewV7()
	_, err := tx.Exec(ctx, `INSERT INTO pc.grants (org_id, id, agent_id, principal_sa_id, environment_id, depth, current_revision,
		grantor_kind, grantor_id, basis, ceiling_id, automation_execution_id)
		VALUES ($1, $2, $3, $4, $5, 0, 1, 'service_account', $4, 'automation refunds', $6, $7)`,
		in.Org, id, in.Agent, in.ServiceAccount, g.f.env, in.Ceiling, in.Execution)
	return id, err
}

func (g *fakeGrants) RevokeForAutomation(ctx context.Context, tx pgx.Tx, in steps.GrantRevoke) ([]ids.UUID, error) {
	return g.revoke(ctx, tx, in.Org, in.Execution, in.Reason)
}

func (g *fakeGrants) RevokeExecutionGrants(ctx context.Context, tx pgx.Tx, x *engine.Exec, reason string) ([]ids.UUID, error) {
	return g.revoke(ctx, tx, x.Org, x.ID, reason)
}

func (g *fakeGrants) revoke(ctx context.Context, tx pgx.Tx, org ids.OrgID, exec ids.UUID, reason string) ([]ids.UUID, error) {
	rows, err := tx.Query(ctx, `UPDATE pc.grants SET state = 'REVOKED', revoked_at = now(), revoke_reason = $3
		WHERE org_id = $1 AND automation_execution_id = $2 AND state = 'ACTIVE' RETURNING id`, org, exec, reason)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[ids.UUID])
	g.revoked = append(g.revoked, out...)
	return out, err
}

// fakeRuns starts the execution's run as core does (launcher = the
// automation's account) and ends it by marking it.
type fakeRuns struct{ f *efx }

func (r fakeRuns) StartForAutomation(ctx context.Context, tx pgx.Tx, in steps.LaunchStart) (ids.UUID, error) {
	id := ids.NewV7()
	_, err := tx.Exec(ctx, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_sa_id, principal_sa_id,
		principal_source, automation_execution_id, grant_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'automation', $6, $7, now() + interval '1 hour')`,
		in.Org, id, in.Agent, r.f.env, in.ServiceAccount, in.Execution, in.Grant)
	return id, err
}

func (r fakeRuns) EndForAutomation(ctx context.Context, tx pgx.Tx, org ids.OrgID, exec, _, run ids.UUID, reason string) error {
	_, err := tx.Exec(ctx, `UPDATE pc.runs SET state = 'ENDED', end_reason = $4, ended_at = now()
		WHERE org_id = $1 AND id = $2 AND automation_execution_id = $3 AND state = 'ACTIVE'`, org, run, exec, reason)
	return err
}

func (r fakeRuns) EndExecutionRuns(ctx context.Context, tx pgx.Tx, x *engine.Exec, reason string) ([]ids.UUID, error) {
	rows, err := tx.Query(ctx, `UPDATE pc.runs SET state = 'ENDED', end_reason = $3, ended_at = now()
		WHERE org_id = $1 AND automation_execution_id = $2 AND state = 'ACTIVE' RETURNING id`, x.Org, x.ID, reason)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[ids.UUID])
}

// gates is steps.Gates over the approvals use cases, as the server wires
// it.
type gates struct{ svc *approvalsapp.Service }

func (g gates) in(r steps.GateRequest) approvalsapp.AutomationGate {
	return approvalsapp.AutomationGate{
		Org: r.Org, Automation: r.Automation, AutomationName: r.AutomationName, ServiceAccount: r.ServiceAccount,
		Execution: r.Execution, StepID: r.StepID, Attempt: r.Attempt, ParamsDigest: r.ParamsDigest, Params: r.Params,
		Summary: r.Summary, Roles: r.Roles, Users: r.Users, Exclude: r.Exclude, MinApprovals: r.MinApprovals,
		Deadline: r.Deadline, Agent: r.Agent,
	}
}

func (g gates) RequestGate(ctx context.Context, tx pgx.Tx, r steps.GateRequest) (ids.UUID, int, error) {
	return g.svc.RequestAutomationGateTx(ctx, tx, g.in(r))
}

func (g gates) EligibleGate(ctx context.Context, tx pgx.Tx, r steps.GateRequest) (int, error) {
	return g.svc.EligibleAutomationGateTx(ctx, tx, g.in(r))
}

func (g gates) GateStatus(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) (steps.GateState, error) {
	st, err := g.svc.AutomationGateStateTx(ctx, tx, org, id)
	return steps.GateState{State: st.State, Approvers: st.Approvers}, err
}

func (g gates) EndGate(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID, reason string) error {
	return g.svc.EndAutomationGateTx(ctx, tx, org, id, reason)
}

func (g gates) ConsumeGate(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) error {
	return g.svc.ConsumeAutomationGateTx(ctx, tx, org, id)
}

// TestHR283_CancelStopsAtTheBoundaryAndReportsItsVerifiedEffect (D28):
// cancelling a waiting execution ends it in one transaction; its grant is
// revoked, its run ended and its launch cancelled, and the effect lists
// exactly those; the launch it already made is reported as a change, never
// undone.
func TestHR283_CancelStopsAtTheBoundaryAndReportsItsVerifiedEffect(t *testing.T) {
	f := newEfx(t, launchSteps)
	exec := f.start("T-1")
	f.advance(exec)
	if s := f.str("SELECT state FROM pc.automation_executions WHERE id = $1", exec); s != "WAITING" {
		t.Fatalf("before the cancel: %s", s)
	}
	launch := f.str("SELECT id::text FROM pc.automation_launches WHERE execution_id = $1", exec)
	sum, eff, err := f.e.CancelExecution(f.manager(), exec, "wrong ticket")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Row.State != string(autodomain.ExecPartiallyCompleted) || sum.Row.Reason == nil ||
		*sum.Row.Reason != autodomain.ReasonCancelledByUser {
		t.Fatalf("after the cancel: %s %v", sum.Row.State, sum.Row.Reason)
	}
	if len(eff.Executions) != 1 || len(eff.Grants) != 1 || len(eff.Runs) != 1 || len(eff.Launches) != 1 ||
		eff.Launches[0].String() != launch {
		t.Fatalf("effect %+v", eff)
	}
	for sql, want := range map[string]string{
		"SELECT state FROM pc.automation_launches WHERE execution_id = $1":                                                   "CANCELLED", //nolint:misspell // stored state
		"SELECT state FROM pc.grants WHERE automation_execution_id = $1":                                                     "REVOKED",
		"SELECT state FROM pc.runs WHERE automation_execution_id = $1":                                                       "ENDED",
		"SELECT count(*)::text FROM pc.automation_step_attempts WHERE execution_id = $1 AND state IN ('RUNNING', 'WAITING')": "0",
	} {
		if got := f.str(sql, exec); got != want {
			t.Errorf("%s = %s, want %s", sql, got, want)
		}
	}
	if sum.Result == nil || len(sum.Result.Changed) != 1 || sum.Result.Changed[0] != "launch" {
		t.Errorf("result %+v", sum.Result)
	}
	// A cancelled execution stays as it is.
	if _, eff, err := f.e.CancelExecution(f.manager(), exec, ""); err != nil || len(eff.Grants) != 0 {
		t.Errorf("a second cancel: %+v %v", eff, err)
	}
}

// TestHR283_KillSwitchCancelsAndPauseLetsWorkFinish (D14, D28): the kill
// switch cancels an active execution at its next boundary; a user pause
// stops nothing that is running.
func TestHR283_KillSwitchCancelsAndPauseLetsWorkFinish(t *testing.T) {
	f := newEfx(t, launchSteps)
	paused, killed := f.start("T-1"), f.start("T-2")
	f.advance(paused)
	f.Pause(t, f.auto)
	f.advance(paused)
	if s := f.str("SELECT state FROM pc.automation_executions WHERE id = $1", paused); s != "WAITING" {
		t.Fatalf("a paused automation's execution %s, want it to go on", s)
	}
	f.Exec(t, `INSERT INTO pc.org_containment (org_id, kill_switch, engaged_by, engaged_at, engage_reason)
		VALUES ($1, true, 'test', now(), 'test')`, f.Org)
	f.advance(killed)
	if s := f.str("SELECT state || ' ' || reason FROM pc.automation_executions WHERE id = $1", killed); s != "CANCELLED KILL_SWITCH" { //nolint:misspell // stored state
		t.Fatalf("under the kill switch: %s", s)
	}
	f.advance(paused)
	if s := f.str("SELECT reason FROM pc.automation_executions WHERE id = $1", paused); s != "KILL_SWITCH" {
		t.Fatalf("the waiting execution under the kill switch: %s", s)
	}
}

// TestT124_ATriggerStartsOneExecutionAndUnknownOutcomesAreNeverRetried
// (HR-277, HR-280): a trigger replayed into the Starter starts nothing a
// second time; an execution whose irreversible outcome is unknown is
// reported so by the lookup retries use.
func TestT124_ATriggerStartsOneExecutionAndUnknownOutcomesAreNeverRetried(t *testing.T) {
	f := newEfx(t, launchSteps)
	exec := f.start("T-1")
	trig := f.str("SELECT trigger_id::text FROM pc.automation_executions WHERE id = $1", exec)
	trigID, _ := ids.ParseUUID(trig)
	err := f.Pool.InTenantTx(context.Background(), f.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := f.e.Start(ctx, tx.Pgx(), autodomain.TriggerRef{
			ID: trigID, Org: f.Org, Automation: f.auto.ID, Version: f.auto.Version, Kind: autodomain.TriggerManual,
			Mode: autodomain.ModeLive, Root: trigID, OccurredAt: time.Now(),
		})
		return err
	})
	if err == nil {
		t.Fatal("a replayed trigger started a second execution")
	}
	f.advance(exec)
	attempt := f.str("SELECT id::text FROM pc.automation_step_attempts WHERE execution_id = $1 AND step_id = 'launch'", exec)
	f.Exec(t, `UPDATE pc.automation_step_attempts SET state = 'UNKNOWN', effect = 'UNKNOWN',
		output = output || '{"irreversible":"true"}' WHERE id = $1`, attempt)
	var info struct {
		unknown bool
		state   autodomain.ExecutionState
	}
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		x, err := f.e.Execution(ctx, tx.Pgx(), f.Org, exec)
		info.unknown, info.state = x.UnknownIrreversible, x.State
		return err
	})
	if !info.unknown {
		t.Fatal("the lookup misses an unknown irreversible outcome")
	}
}

// TestT125_AGateApprovalNeverCarriesToAnotherExecution (HR-281): two
// executions wait at the same gate; an Automation Operator approves the
// first with a key; only the first goes on, consuming its approval once;
// the second's request stays its own and expires at the gate's deadline.
func TestT125_AGateApprovalNeverCarriesToAnotherExecution(t *testing.T) {
	f := newEfx(t, gateSteps)
	op := ids.NewV7()
	secret := bytes.Repeat([]byte{9}, 32)
	cred, browser := ids.NewV7(), ids.NewV7()
	f.Exec(t, `INSERT INTO pc.users (org_id, id, issuer, subject, created_at) VALUES ($1, $2, 'https://idp.test', 'olga',
		now() - interval '30 days')`, f.Org, op)
	f.Exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name, created_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key',
		now() - interval '30 days')`, f.Org, cred, op, secret[:16], secret)
	f.Exec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, f.Org, browser, op, secret)
	f.Exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
		VALUES ($1, $2, 'automation_operator', $3, 'ORG', 'test', now() - interval '30 days')`, f.Org, ids.NewV7(), op)

	first, second := f.start("T-1"), f.start("T-2")
	f.advance(first)
	f.advance(second)
	req := func(exec ids.UUID) ids.UUID {
		id, err := ids.ParseUUID(f.str("SELECT id::text FROM pc.approval_requests WHERE execution_id = $1", exec))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	r1, r2 := req(first), req(second)
	if f.str("SELECT (a.binding <> b.binding)::text FROM pc.approval_requests a, pc.approval_requests b WHERE a.id = $1 AND b.id = $2",
		r1, r2) != "true" {
		t.Fatal("two executions' gates share a binding")
	}
	ceremony := ids.NewV7()
	f.Exec(t, `INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, approval_request_id, expires_at)
		SELECT $1, $2, $3, $4, 'BINDING', binding, id, now() + interval '5 minutes' FROM pc.approval_requests WHERE id = $5`,
		f.Org, ceremony, browser, op, r1)
	if _, err := f.approvals.Approve(context.Background(), f.Org, approvalsapp.Responder{User: op, Browser: browser}, r1,
		approvalsapp.Assertion{
			Ceremony: ceremony, Credential: cred, AuthenticatorData: make([]byte, 37),
			ClientDataJSON: []byte(`{}`), Signature: []byte{1},
		}); err != nil {
		t.Fatal(err)
	}
	// The ceremony of the first never approves the second.
	if _, err := f.approvals.Approve(context.Background(), f.Org, approvalsapp.Responder{User: op, Browser: browser}, r2,
		approvalsapp.Assertion{
			Ceremony: ceremony, Credential: cred, AuthenticatorData: make([]byte, 37),
			ClientDataJSON: []byte(`{}`), Signature: []byte{1},
		}); !errors.Is(err, approvalsapp.ErrCeremony) {
		t.Fatalf("a reused ceremony: %v", err)
	}
	f.advance(first)
	f.advance(second)
	if s := f.str("SELECT state FROM pc.approval_requests WHERE id = $1", r1); s != "CONSUMED" {
		t.Fatalf("the first gate's request: %s", s)
	}
	if s := f.str("SELECT state FROM pc.automation_step_attempts WHERE execution_id = $1", first); s != "DONE" {
		t.Fatalf("the first gate: %s", s)
	}
	if s := f.str("SELECT state FROM pc.automation_step_attempts WHERE execution_id = $1", second); s != "WAITING" {
		t.Fatalf("the second gate went on with another execution's approval: %s", s)
	}
	f.Exec(t, `UPDATE pc.automation_step_attempts SET output = output || jsonb_build_object('deadline',
		to_char((now() - interval '1 minute') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')) WHERE execution_id = $1`, second)
	f.advance(second)
	if s := f.str("SELECT state || ' ' || reason FROM pc.automation_step_attempts WHERE execution_id = $1", second); s != "FAILED GATE_EXPIRED" {
		t.Fatalf("the expired gate: %s", s)
	}
	if s := f.str("SELECT state FROM pc.approval_requests WHERE id = $1", r2); s != "EXPIRED" {
		t.Fatalf("the expired gate's request: %s", s)
	}
}
