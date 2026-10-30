// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package cohorts_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/cohorts"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type team struct{}

func (team) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = billing.Team
	return x, nil
}

type world struct {
	t            *testing.T
	pool         *db.Pool
	org          ids.OrgID
	teamA, teamB ids.UUID
	envA, envB   ids.UUID
	owner        ids.UUID
	a1, b1       ids.UUID
	svc          *cohorts.Service
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) count(sql string) int {
	w.t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql).Scan(&n)
	}); err != nil {
		w.t.Fatal(err)
	}
	return n
}

func newWorld(t *testing.T) *world {
	t.Helper()
	return newWorldOn(t, dbtest.New(t))
}

// newWorldOn builds the world on a test database.
func newWorldOn(t *testing.T, d *dbtest.DB) *world {
	t.Helper()
	p := d.AppPool(t)
	w := &world{
		t: t, pool: p, org: ids.New[ids.Org](), teamA: ids.NewV7(), teamB: ids.NewV7(), envA: ids.NewV7(), envB: ids.NewV7(),
		owner: ids.NewV7(), a1: ids.NewV7(), b1: ids.NewV7(),
	}
	w.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec("INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'a', 'A'), ($1, $3, 'b', 'B')", w.org, w.teamA, w.teamB)
	w.exec(`INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT'),
		($1, $4, $5, 'dev', 'Dev', 'DEVELOPMENT')`, w.org, w.envA, w.teamA, w.envB, w.teamB)
	w.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'owner')", w.org, w.owner)
	for i, a := range []struct{ id, team, env ids.UUID }{{w.a1, w.teamA, w.envA}, {w.b1, w.teamB, w.envB}} {
		w.exec(`INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'service', 'VERIFIED', 'test', now())`, w.org, a.id, fmt.Sprintf("bot-%d", i), a.team, a.env, w.owner)
	}
	w.svc = &cohorts.Service{Pool: p, Editions: team{}}
	return w
}

// as is a person holding role at scope (nil: the org).
func (w *world) as(role td.RoleName, scope *td.Scope) context.Context {
	s := td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}
	if scope != nil {
		s = *scope
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject:    td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: []td.Binding{{Role: role, Scope: s}}},
		Credential: tapp.CredBrowserSession,
	})
}

// TestHR291_CohortsAreManagedAndSeenWithinTheirScope (D40, D71 G4, G8): a
// team-scoped fleet manager manages its team's cohorts and members but no
// other team's and no org-wide rule; a reader outside a cohort's scope
// neither gets nor lists it, and nothing counts what they cannot see.
func TestHR291_CohortsAreManagedAndSeenWithinTheirScope(t *testing.T) {
	w := newWorld(t)
	teamA := &td.Scope{Type: td.ScopeTeam, ID: w.teamA}
	mgrA := w.as(td.RoleFleetManager, teamA)
	ruleA := cohorts.Input{Name: "team-a", Owner: w.owner, Rule: &cohorts.Rule{TeamID: &w.teamA}}
	coA, err := w.svc.Create(mgrA, ruleA)
	if err != nil {
		t.Fatalf("a team manager's team cohort: %v", err)
	}
	if _, err := w.svc.Create(mgrA, cohorts.Input{Name: "team-b", Owner: w.owner, Rule: &cohorts.Rule{TeamID: &w.teamB}}); err == nil {
		t.Error("a team manager created another team's cohort")
	}
	if _, err := w.svc.Create(mgrA, cohorts.Input{Name: "refunds", Owner: w.owner, Rule: &cohorts.Rule{TaskType: "refunds"}}); err == nil {
		t.Error("a team manager created an org-wide rule")
	}
	if n, err := w.svc.ChangeMembers(mgrA, coA.ID, []ids.UUID{w.a1}, false); err != nil || n != 1 {
		t.Fatalf("adding the team's agent: %d %v", n, err)
	}
	if _, err := w.svc.ChangeMembers(mgrA, coA.ID, []ids.UUID{w.b1}, false); err == nil {
		t.Error("a team manager added another team's agent")
	}
	if err := w.svc.SetAgentTaskType(mgrA, w.a1, "refunds"); err != nil {
		t.Errorf("task type of the team's agent: %v", err)
	}
	if err := w.svc.SetAgentTaskType(mgrA, w.b1, "refunds"); err == nil {
		t.Error("task type of another team's agent")
	}
	org := w.as(td.RoleFleetManager, nil)
	if _, err := w.svc.ChangeMembers(org, coA.ID, []ids.UUID{w.b1}, false); err != nil {
		t.Fatalf("an org manager widening the cohort: %v", err)
	}
	if err := w.svc.Delete(mgrA, coA.ID); err == nil {
		t.Error("a team manager deleted a cohort that now spans two teams")
	}
	if _, err := w.svc.ChangeMembers(org, coA.ID, []ids.UUID{w.b1}, true); err != nil {
		t.Fatal(err)
	}

	readerB := w.as(td.RoleResponder, &td.Scope{Type: td.ScopeTeam, ID: w.teamB})
	if _, err := w.svc.Get(readerB, coA.ID); !errors.Is(err, cohorts.ErrNotFound) {
		t.Errorf("a reader of team B got team A's cohort: %v", err)
	}
	if cs, _, err := w.svc.List(readerB, "", 0); err != nil || len(cs) != 0 {
		t.Errorf("a reader of team B lists %d cohorts (%v)", len(cs), err)
	}
	if _, _, err := w.svc.Members(readerB, coA.ID, nil, 0); !errors.Is(err, cohorts.ErrNotFound) {
		t.Errorf("a reader of team B read team A's members: %v", err)
	}
	readerA := w.as(td.RoleResponder, teamA)
	ms, _, err := w.svc.Members(readerA, coA.ID, nil, 0)
	if err != nil || len(ms) != 1 || ms[0].Agent.ID != w.a1 {
		t.Fatalf("team A's members: %+v %v", ms, err)
	}
	o, err := w.svc.GetFleetOverview(readerA, nil, 0)
	if err != nil || len(o.Agents) != 1 {
		t.Fatalf("team A's overview: %+v %v", o, err)
	}
}

// TestHR291_ABaselineOnlyReportsGrantsBeyondIt (D40): a cohort with a
// baseline lists the active grants beyond it in its queue; creating the
// cohort, adding members and reading the queue issue, revise and revoke
// nothing.
func TestHR291_ABaselineOnlyReportsGrantsBeyondIt(t *testing.T) {
	w := newWorld(t)
	gs := &gpg.Store{Pool: w.pool}
	grants := &gapp.Service{Repo: gs, Subjects: gs, Defs: &defpg.Store{Pool: w.pool}, Authz: gapp.SubjectAuthorizer{}, Clock: clock.System{}}
	issuer := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org:       w.org,
		Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.owner},
		Bindings:  []td.Binding{{Role: td.RoleGrantIssuer, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
	}})
	issue := func(bounds string) gdomain.Grant {
		b, _ := gdomain.DecodeBounds([]byte(bounds))
		g, err := grants.Issue(issuer, gapp.IssueRequest{
			AgentID: w.a1, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.owner},
			TaskRef: "refunds", ExpiresAt: time.Now().Add(24 * time.Hour), Bounds: b,
		})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	within := issue(`{"operations": ["payments.refund.get"]}`)
	wider := issue(`{"operations": ["payments.refund.get", "payments.refund.create"]}`)
	before := w.count("SELECT count(*) FROM pc.grant_revisions")

	org := w.as(td.RoleFleetManager, nil)
	baseline, err := cohorts.DecodeBaseline([]byte(`{"bounds": {"operations": ["payments.refund.get"]}, "ttl_seconds": 172800}`))
	if err != nil {
		t.Fatal(err)
	}
	co, err := w.svc.Create(org, cohorts.Input{Name: "refunders", Owner: w.owner, Baseline: baseline})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.ChangeMembers(org, co.ID, []ids.UUID{w.a1}, false); err != nil {
		t.Fatal(err)
	}
	q, err := w.svc.GetQueue(w.as(td.RoleResponder, nil), co.ID)
	if err != nil {
		t.Fatal(err)
	}
	var over []ids.UUID
	for _, d := range q.OverBaseline {
		over = append(over, d.Grant)
	}
	if !slices.Equal(over, []ids.UUID{wider.ID.UUID()}) || slices.Contains(over, within.ID.UUID()) || q.Truncated {
		t.Fatalf("over the baseline %v (truncated %v), want only %s", over, q.Truncated, wider.ID)
	}
	if after := w.count("SELECT count(*) FROM pc.grant_revisions"); after != before {
		t.Fatalf("organizing changed grants: %d revisions, was %d", after, before)
	}
	if n := w.count("SELECT count(*) FROM pc.agent_promotions"); n != 0 {
		t.Fatalf("organizing promoted %d", n)
	}
}

// TestHR291_AnAgentsBaselineIsItsOneCohorts (D115 R2b): BaselineForAgent
// reads, in the caller's transaction, the baseline of the one cohort with
// a baseline the agent is in, statically or by rule; none is NO_BASELINE,
// several COHORT_AMBIGUOUS, and a cohort without a baseline counts for
// nothing.
func TestHR291_AnAgentsBaselineIsItsOneCohorts(t *testing.T) {
	w := newWorld(t)
	org := w.as(td.RoleFleetManager, nil)
	baselineFor := func(agent ids.UUID) (cohorts.Baseline, ids.UUID, error) {
		var b cohorts.Baseline
		var id ids.UUID
		err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			b, id, err = cohorts.BaselineForAgent(ctx, tx, w.org, agent)
			return err
		})
		return b, id, err
	}
	if _, _, err := baselineFor(w.a1); pcerr.ReasonOf(err) != "NO_BASELINE" {
		t.Fatalf("no cohort: %v, want NO_BASELINE", err)
	}
	if _, err := w.svc.Create(org, cohorts.Input{Name: "plain", Owner: w.owner, Rule: &cohorts.Rule{TeamID: &w.teamA}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := baselineFor(w.a1); pcerr.ReasonOf(err) != "NO_BASELINE" {
		t.Fatalf("a cohort without a baseline: %v, want NO_BASELINE", err)
	}
	gets, _ := cohorts.DecodeBaseline([]byte(`{"bounds": {"operations": ["payments.refund.get"]}, "ttl_seconds": 3600}`))
	static, err := w.svc.Create(org, cohorts.Input{Name: "refund-readers", Owner: w.owner, Baseline: gets})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.ChangeMembers(org, static.ID, []ids.UUID{w.a1}, false); err != nil {
		t.Fatal(err)
	}
	b, id, err := baselineFor(w.a1)
	if err != nil || id != static.ID || b.TTLSeconds != 3600 || b.Bounds.Operations == nil || (*b.Bounds.Operations)[0] != "payments.refund.get" {
		t.Fatalf("one cohort: %+v %s %v", b, id, err)
	}
	if _, _, err := baselineFor(w.b1); pcerr.ReasonOf(err) != "NO_BASELINE" {
		t.Fatalf("another agent: %v, want NO_BASELINE", err)
	}
	creates, _ := cohorts.DecodeBaseline([]byte(`{"bounds": {"operations": ["payments.refund.create"]}}`))
	if _, err := w.svc.Create(org, cohorts.Input{Name: "team-a-refunders", Owner: w.owner, Rule: &cohorts.Rule{TeamID: &w.teamA}, Baseline: creates}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := baselineFor(w.a1); pcerr.ReasonOf(err) != "COHORT_AMBIGUOUS" {
		t.Fatalf("two cohorts with baselines: %v, want COHORT_AMBIGUOUS", err)
	}
}
