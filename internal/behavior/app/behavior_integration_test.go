// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	bapp "github.com/katocxl/pantherclaw/internal/behavior/app"
	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	"github.com/katocxl/pantherclaw/internal/behavior/simhistory"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = billing.Edition(e)
	return x, nil
}

// fx is a Business org with a real agent and a range agent, each with a run.
type fx struct {
	t                  *testing.T
	d                  *dbtest.DB
	p                  *db.Pool
	org                ids.OrgID
	team, other, env   ids.UUID
	user               ids.UUID
	agent, run         ids.UUID
	rangeAgent, simRun ids.UUID
	roll               *bapp.Rollup
	svc                *bapp.Service
}

func newFx(t *testing.T) *fx {
	t.Helper()
	d := dbtest.New(t)
	f := &fx{
		t: t, d: d, p: d.AppPool(t), org: ids.New[ids.Org](), team: ids.NewV7(), other: ids.NewV7(), env: ids.NewV7(),
		user: ids.NewV7(), agent: ids.NewV7(), run: ids.NewV7(), rangeAgent: ids.NewV7(), simRun: ids.NewV7(),
	}
	f.roll = &bapp.Rollup{Pool: f.p, Ents: edition(billing.Business), Raiser: &alerts.Raiser{}, Failures: &failures.Sink{}, Settle: time.Nanosecond}
	f.svc = &bapp.Service{Pool: f.p, Ents: edition(billing.Business)}
	f.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", f.org)
	f.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.user)
	f.exec("INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'a', 'A'), ($1, $3, 'b', 'B')", f.org, f.team, f.other)
	f.exec("INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'a', 'A', 'PRODUCTION')", f.org, f.env, f.team)
	for _, a := range []struct {
		id, run ids.UUID
		name    string
		rng     bool
	}{{f.agent, f.run, "bot", false}, {f.rangeAgent, f.simRun, "range-bot", true}} {
		f.exec(`INSERT INTO pc.agents (org_id, id, name, state, created_by, team_id, environment_id, owner_user_id, execution_context, claimed_at, range_agent)
			VALUES ($1, $2, $3, 'VERIFIED', 'test', $4, $5, $6, 'service', now(), $7)`, f.org, a.id, a.name, f.team, f.env, f.user, a.rng)
		f.exec(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at, simulated)
			VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '1 hour', $6)`, f.org, a.run, a.id, f.env, f.user, a.rng)
	}
	return f
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// txn records one decision on run at, simulated when the run is.
func (f *fx) txn(run ids.UUID, simulated bool, operation, decision string, at time.Time) ids.UUID {
	f.t.Helper()
	id := ids.NewV7()
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, mode, simulated, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'R', 'gw', 'enforce', $8, $9)`,
		f.org, id, run, ids.NewV7(), make([]byte, 32), operation, decision, simulated, at)
	return id
}

// history is ten days of the real agent's usual work: three runs a day of
// read then write, around this hour of the day.
func (f *fx) history() {
	f.t.Helper()
	now := time.Now()
	for d := 1; d <= 10; d++ {
		for r := range 3 {
			at := now.AddDate(0, 0, -d).Add(-time.Duration(r*5) * time.Minute)
			f.txn(f.run, false, "repo.read", "ALLOW", at)
			f.txn(f.run, false, "repo.write", "ALLOW", at.Add(time.Minute))
		}
	}
}

func (f *fx) rollup() bapp.Result {
	f.t.Helper()
	res, err := f.roll.Run(context.Background(), f.org)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

func (f *fx) as(role td.RoleName, scope td.Scope) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.user},
		Bindings: []td.Binding{{Role: role, Scope: scope}},
	}})
}

func (f *fx) responder() context.Context {
	return f.as(td.RoleResponder, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
}

// simulate gives the range agent a fortnight of generated history.
func (f *fx) simulate(agent ids.UUID) error {
	return f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := simhistory.Store(ctx, tx, simhistory.Spec{
			Agent: agent, DestClass: "INTERNAL", Operations: []string{"repo.read", "repo.write"},
			Days: 14, RunsPerDay: 3, Hour: time.Now().UTC().Hour(), End: time.Now(), Seed: 27,
		})
		return err
	})
}

// TestHR642_RealAndSimulatedNeverMeet: one rollup keeps a real agent's
// profile on its real transactions and a range agent's on its simulated
// ones and its generated history; neither has a profile of the other kind.
// A first run only starts collection. Afterwards a new tool raises labelled
// inference on each side: the real one an alert, the simulated one a test
// alert. None opens an incident, and none is a CONFIRMED alert (HR-640,
// HR-644). The database refuses generated history for a real agent.
// Covers: F930, F931, F932
func TestHR642_RealAndSimulatedNeverMeet(t *testing.T) {
	f := newFx(t)
	f.history()
	if err := f.simulate(f.rangeAgent); err != nil {
		t.Fatal(err)
	}
	var pgErr *pgconn.PgError
	if err := f.simulate(f.agent); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("generated history for a real agent: %v", err)
	}

	if res := f.rollup(); res.Profiles != 2 || res.Signals != 0 {
		t.Fatalf("first run: %+v", res)
	}
	real, err := f.svc.Profile(f.responder(), f.agent, bdomain.OriginReal)
	if err != nil || real.State != bdomain.StateCollected || real.Actions != 60 || real.ActiveDays != 10 {
		t.Fatalf("real profile: %+v %v", real, err)
	}
	sim, err := f.svc.Profile(f.responder(), f.rangeAgent, bdomain.OriginSimulated)
	if err != nil || sim.State != bdomain.StateCollected || sim.Actions != 14*3*2 {
		t.Fatalf("simulated profile: %+v %v", sim, err)
	}
	for _, x := range []struct {
		agent  ids.UUID
		origin bdomain.Origin
	}{{f.agent, bdomain.OriginSimulated}, {f.rangeAgent, bdomain.OriginReal}} {
		if p, err := f.svc.Profile(f.responder(), x.agent, x.origin); err != nil || p.State != bdomain.StateNotCollected {
			t.Fatalf("%s profile of %s: %+v %v", x.origin, x.agent, p, err)
		}
	}

	f.txn(f.run, false, "secrets.dump", "ALLOW", time.Now())
	f.txn(f.simRun, true, "secrets.dump", "ALLOW", time.Now())
	if res := f.rollup(); res.Signals < 2 {
		t.Fatalf("second run: %+v", res)
	}
	const tool = `SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND source = 'behavior' AND rule_id = 'pc.drift.behavior.new_tool'
		AND basis = 'INFERRED' AND attention IN ('FINDING', 'ALERT') AND incident_id IS NULL AND test = $2 AND group_key = $3
		AND facts ->> 'definition_status' = 'UNVALIDATED'`
	if n := f.count(tool, f.org, false, "agent:"+f.agent.String()); n != 1 {
		t.Fatalf("real new-tool alerts = %d", n)
	}
	if n := f.count(tool, f.org, true, "agent:"+f.rangeAgent.String()); n != 1 {
		t.Fatalf("simulated new-tool alerts = %d", n)
	}
	if n := f.count("SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND source = 'behavior' AND (basis <> 'INFERRED' OR incident_id IS NOT NULL OR attention IN ('INCIDENT', 'PAGE'))", f.org); n != 0 {
		t.Fatalf("%d behaviour alerts claim more than inference", n)
	}
	if n := f.count("SELECT count(*) FROM pc.incidents WHERE org_id = $1", f.org); n != 0 {
		t.Fatalf("%d incidents", n)
	}
	// Nothing new: a third run raises nothing.
	if res := f.rollup(); res.Signals != 0 {
		t.Fatalf("third run: %+v", res)
	}
}

// TestHR643_TheRollupPagesAndReportsItsCaps: a run compares at most its page
// of actions since the cursor and moves the cursor over that page only; the
// next runs carry on, so every new action is compared once. A cap that bites,
// on the page or on an agent's baseline, is reported as BEHAVIOR_CAP_REACHED
// (D526). Covers: F930, F931
func TestHR643_TheRollupPagesAndReportsItsCaps(t *testing.T) {
	f := newFx(t)
	f.history()
	f.rollup()
	f.roll.MaxBatch = 3
	at := time.Now()
	for i := range 5 {
		f.txn(f.run, false, "odd.tool"+string(rune('a'+i)), "ALLOW", at.Add(time.Duration(i)*time.Millisecond))
	}
	// The first page is a, b and c: c's instant is left for the next run.
	const cursor = `SELECT count(*) FROM pc.behavior_cursors WHERE org_id = $1 AND origin = 'REAL'
		AND scanned_to = (SELECT created_at FROM pc.transactions WHERE org_id = $1 AND operation = 'odd.toolc')`
	const capped = `SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = 'behavior.cap_reached' AND state = 'OPEN'`
	f.rollup()
	if n := f.count(cursor, f.org); n != 1 {
		t.Fatal("the cursor moved past what the first page processed")
	}
	if n := f.count(capped, f.org); n != 1 {
		t.Fatalf("cap failures = %d", n)
	}
	f.rollup()
	f.rollup()
	const tools = `SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND rule_id = 'pc.drift.behavior.new_tool' AND facts ->> 'value' LIKE 'odd.tool%'`
	if n := f.count(tools, f.org); n != 5 {
		t.Fatalf("new-tool alerts after paging = %d, want 5", n)
	}

	// A baseline cap is per agent, and reported too.
	g := newFx(t)
	g.history()
	g.roll.MaxBaseline = 10
	if res := g.rollup(); res.Profiles != 1 {
		t.Fatalf("profiles = %+v", res)
	}
	if p, err := g.svc.Profile(g.responder(), g.agent, bdomain.OriginReal); err != nil || p.Actions != 10 || !p.Truncated {
		t.Fatalf("capped baseline: %+v %v", p, err)
	}
	if n := g.count(capped, g.org); n != 1 {
		t.Fatalf("baseline cap failures = %d", n)
	}
}

// TestHR643_NotCollectedIsNeverZero: before any rollup a profile is
// NOT_COLLECTED, and an agent with little history is INSUFFICIENT_HISTORY
// and raises nothing, however odd its next action. Covers: F930
func TestHR643_NotCollectedIsNeverZero(t *testing.T) {
	f := newFx(t)
	p, err := f.svc.Profile(f.responder(), f.agent, bdomain.OriginReal)
	if err != nil || p.State != bdomain.StateNotCollected || p.Actions != 0 {
		t.Fatalf("before any rollup: %+v %v", p, err)
	}
	f.txn(f.run, false, "repo.read", "ALLOW", time.Now().Add(-time.Hour))
	f.rollup()
	f.txn(f.run, false, "secrets.dump", "ALLOW", time.Now())
	if res := f.rollup(); res.Signals != 0 {
		t.Fatalf("inferred from one action: %+v", res)
	}
	if p, err = f.svc.Profile(f.responder(), f.agent, bdomain.OriginReal); err != nil || p.State != bdomain.StateInsufficient {
		t.Fatalf("after: %+v %v", p, err)
	}
}

// TestHR646_ProfilesAreScopedAndGated: a role without behavior.read is
// refused, a viewer scoped to another team finds nothing, and a Community
// edition is refused. Covers: F930
func TestHR646_ProfilesAreScopedAndGated(t *testing.T) {
	f := newFx(t)
	viewer := f.as(td.RoleViewer, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
	if _, err := f.svc.Profile(viewer, f.agent, bdomain.OriginReal); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("viewer: %v", err)
	}
	elsewhere := f.as(td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: f.other})
	if _, err := f.svc.Profile(elsewhere, f.agent, bdomain.OriginReal); !errors.Is(err, bapp.ErrNotFound) {
		t.Fatalf("another team: %v", err)
	}
	here := f.as(td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: f.team})
	if _, err := f.svc.Profile(here, f.agent, bdomain.OriginReal); err != nil {
		t.Fatalf("its team: %v", err)
	}
	community := &bapp.Service{Pool: f.p, Ents: edition(billing.Community)}
	if _, err := community.Profile(f.responder(), f.agent, bdomain.OriginReal); !errors.Is(err, bapp.ErrEdition) {
		t.Fatalf("community: %v", err)
	}
}

// TestHR645_ApprovalContextIsOutsideTheBinding: what stands out about a held
// action shows beside its approval request, and reading it changes nothing
// the request binds or decides. A restoration has no action and no context.
// Covers: F934
func TestHR645_ApprovalContextIsOutsideTheBinding(t *testing.T) {
	f := newFx(t)
	f.history()
	f.rollup()

	grant, req := ids.NewV7(), ids.NewV7()
	binding := sha256.Sum256(req[:])
	f.exec(`INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, f.org, grant, f.agent, f.user, f.env)
	txn := f.txn(f.run, false, "repo.delete", "REQUIRE_APPROVAL", time.Now())
	f.exec(`INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, 'repo.delete', $7, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1}]', '{}', $7, '\x7b7d', date_trunc('second', now()) + interval '1 hour')`,
		f.org, req, f.agent, txn, f.run, grant, binding[:])

	const snapshot = `SELECT md5(binding::text || display::text || display_hash::text || state || coalesce(first_decided_at::text, ''))
		FROM pc.approval_requests WHERE org_id = $1 AND id = $2`
	read := func() string {
		var s string
		if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, snapshot, f.org, req).Scan(&s)
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// The hold, a denied retry and a rollup after them: none makes the held
	// tool known (D526).
	f.txn(f.run, false, "repo.delete", "DENY", time.Now())
	f.rollup()
	stored, err := f.svc.Profile(f.responder(), f.agent, bdomain.OriginReal)
	if err != nil || stored.Body.NotAllowed != 2 || stored.Actions != 60 {
		t.Fatalf("stored profile: %+v %v", stored, err)
	}
	for _, tool := range stored.Body.Tools {
		if tool.Operation == "repo.delete" {
			t.Fatalf("a held action became known: %+v", stored.Body.Tools)
		}
	}

	before := read()
	approver := f.as(td.RoleApprover, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
	c, err := f.svc.Context(approver, req)
	if err != nil {
		t.Fatal(err)
	}
	if c.Agent != f.agent || c.Profile.State != bdomain.StateCollected || len(c.Lines) != 1 || c.Lines[0].Kind != bdomain.KindNewTool {
		t.Fatalf("context = %+v", c)
	}
	// Another person who is a Responder may read the agent's behaviour but
	// not the approval (not its launcher, principal or a decider): the
	// context isn't found for them (D526 P5).
	bob := ids.NewV7()
	f.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", f.org, bob)
	responder := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: bob},
		Bindings: []td.Binding{{Role: td.RoleResponder, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
	}})
	if _, err := f.svc.Profile(responder, f.agent, bdomain.OriginReal); err != nil {
		t.Fatalf("responder reads the profile: %v", err)
	}
	if _, err := f.svc.Context(responder, req); !errors.Is(err, bapp.ErrNotFound) {
		t.Fatalf("responder without approval.read: %v", err)
	}
	if after := read(); after != before {
		t.Fatal("reading the context changed the request")
	}

	restore := ids.NewV7()
	f.exec(`INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, requested_by, operation, binding, binding_input,
		requirements, display, display_hash, deadline_at)
		VALUES ($1, $2, 'RESTORATION', $3, $4, 'agent.restore', $5, '\x7b7d', '[{"kind":"approval","role":"approver","count":1,"sources":[]}]',
		        '{}', $5, date_trunc('second', now()) + interval '1 day')`,
		f.org, restore, f.agent, f.user, append(append([]byte{}, restore[:]...), restore[:]...))
	if _, err := f.svc.Context(approver, restore); !errors.Is(err, bapp.ErrNotFound) {
		t.Fatalf("restoration: %v", err)
	}
}
