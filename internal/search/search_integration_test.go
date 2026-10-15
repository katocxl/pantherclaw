// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package search

import (
	"context"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fx is an org with two teams, an agent in each with transactions, and an
// agent in a third team with none.
type fx struct {
	t                   *testing.T
	p                   *db.Pool
	s                   *Service
	org                 ids.OrgID
	teamA, teamB, teamC ids.UUID
	agentA, agentB      ids.UUID
	agentC              ids.UUID
	user                ids.UUID
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

func (f *fx) agent(team ids.UUID, slug, kind string) (agent, env ids.UUID) {
	agent, env = ids.NewV7(), ids.NewV7()
	f.exec("INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, $3, $3)", f.org, team, slug)
	f.exec("INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, $4, $4, $5)",
		f.org, env, team, slug+"-env", kind)
	f.exec(`INSERT INTO pc.agents (org_id, id, name, state, team_id, environment_id, owner_user_id, execution_context,
		claimed_at, created_by) VALUES ($1, $2, $3, 'CLAIMED', $4, $5, $6, 'ci', now(), 'test')`, f.org, agent, slug, team, env, f.user)
	return agent, env
}

func (f *fx) txns(agent, env ids.UUID, decisions ...string) {
	run := ids.NewV7()
	f.exec(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, f.org, run, agent, env, f.user)
	for _, d := range decisions {
		f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
			VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', $6, 'R', 'gw', 'OPEN')`,
			f.org, ids.NewV7(), run, ids.NewV7(), make([]byte, 32), d)
	}
}

func newFx(t *testing.T) *fx {
	t.Helper()
	d := dbtest.New(t)
	f := &fx{t: t, p: d.AppPool(t), org: ids.New[ids.Org](), teamA: ids.NewV7(), teamB: ids.NewV7(), teamC: ids.NewV7(), user: ids.NewV7()}
	f.s = &Service{Pool: f.p}
	f.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", f.org)
	f.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.user)
	var envA, envB ids.UUID
	f.agentA, envA = f.agent(f.teamA, "alpha", "PRODUCTION")
	f.agentB, envB = f.agent(f.teamB, "bravo", "DEVELOPMENT")
	f.agentC, _ = f.agent(f.teamC, "charlie", "DEVELOPMENT")
	f.txns(f.agentA, envA, "ALLOW", "ALLOW", "ALLOW")
	f.txns(f.agentB, envB, "ALLOW", "DENY")
	return f
}

func (f *fx) caller(role td.RoleName, scope td.Scope) tenancy.Caller {
	return tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.user},
		Bindings: []td.Binding{{Role: role, Scope: scope}},
	}}
}

// search runs q for c past the search.read gate (which the M10 core
// stream adds to the catalog): the scope and filters under test are the
// same.
func (f *fx) search(c tenancy.Caller, q Query) Result {
	f.t.Helper()
	if err := q.Validate(); err != nil {
		f.t.Fatal(err)
	}
	var out Result
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = f.s.run(ctx, c, tx, q, page.Request{Size: 2})
		return err
	}, db.ReadOnly()); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func agentsOf(r Result) []string {
	var out []string
	for _, i := range r.Items {
		out = append(out, i.Fields["agent"])
	}
	return out
}

// TestHR257_SearchReadsAndCountsOnlyTheViewersScope (T-042): a viewer
// whose evidence.read covers one team sees that team's agents' rows only,
// and the count leaves the other team's rows out, so nothing about hidden
// rows can be inferred from it. The omission note comes from the viewer's
// scope; the org-wide viewer gets every row and no such note.
func TestHR257_SearchReadsAndCountsOnlyTheViewersScope(t *testing.T) {
	f := newFx(t)
	org := f.caller(td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
	team := f.caller(td.RoleDeveloper, td.Scope{Type: td.ScopeTeam, ID: f.teamA})
	q := Query{Entity: EntityTransactions}

	all := f.search(org, q)
	if all.Count != 5 || !all.Scope.All || len(all.Omissions) != 0 || all.Next == "" {
		t.Fatalf("org viewer: count %d, scope %+v, omissions %v, next %q", all.Count, all.Scope, all.Omissions, all.Next)
	}
	mine := f.search(team, q)
	if mine.Count != 3 || mine.Scope.All || len(mine.Scope.Agents) != 1 {
		t.Fatalf("team viewer: count %d, scope %+v", mine.Count, mine.Scope)
	}
	for _, a := range agentsOf(mine) {
		if a != f.agentA.String() {
			t.Fatalf("team viewer sees agent %s", a)
		}
	}
	if len(mine.Omissions) != 1 || mine.Omissions[0].Code != omissionScopeLimited {
		t.Fatalf("team viewer omissions: %v", mine.Omissions)
	}
	// Naming the hidden agent finds nothing and says so without revealing
	// that its rows exist: the same answer as for an agent with no rows.
	hidden := f.search(team, Query{Entity: EntityTransactions, Filters: Filters{Agent: &f.agentB}})
	none := f.search(team, Query{Entity: EntityTransactions, Filters: Filters{Agent: &f.agentC}})
	if hidden.Count != 0 || len(hidden.Items) != 0 || hidden.Empty != none.Empty || hidden.Empty != EmptyNothingInScope {
		t.Fatalf("hidden agent: %+v vs %+v", hidden, none)
	}
	// Denials: only team B has one, which the team A viewer never counts.
	if d := f.search(team, Query{Entity: EntityTransactions, Filters: Filters{Decisions: []string{"DENY"}}}); d.Count != 0 {
		t.Fatalf("team viewer counts a hidden denial: %d", d.Count)
	}
	if d := f.search(org, Query{Entity: EntityTransactions, Filters: Filters{Decisions: []string{"DENY"}}}); d.Count != 1 {
		t.Fatalf("org viewer denials: %d", d.Count)
	}
	// Agents and runs follow the same scope.
	if a := f.search(team, Query{Entity: EntityAgents}); a.Count != 1 || len(a.Items) != 1 || a.Items[0].ID != f.agentA.String() {
		t.Fatalf("team viewer agents: %+v", a.Items)
	}
	if r := f.search(team, Query{Entity: EntityRuns}); r.Count != 1 {
		t.Fatalf("team viewer runs: %d", r.Count)
	}
}

// TestHR257_EmptyResultsGiveTheirReason (F627): RESTRICTED when the viewer
// holds the entity's permission nowhere, NO_DATA_COLLECTED when nothing is
// recorded in its scope, NOTHING_IN_SCOPE when data in scope does not
// match; none of them depends on rows outside the scope.
func TestHR257_EmptyResultsGiveTheirReason(t *testing.T) {
	f := newFx(t)
	launcher := f.caller(td.RoleRunLauncher, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
	teamC := f.caller(td.RoleDeveloper, td.Scope{Type: td.ScopeTeam, ID: f.teamC})
	teamA := f.caller(td.RoleDeveloper, td.Scope{Type: td.ScopeTeam, ID: f.teamA})

	if r := f.search(launcher, Query{Entity: EntityAudit}); r.Empty != EmptyRestricted || r.Count != 0 {
		t.Errorf("no audit.read: %+v", r)
	}
	if r := f.search(teamC, Query{Entity: EntityTransactions}); r.Empty != EmptyNoDataCollected {
		t.Errorf("team C: %s", r.Empty)
	}
	if r := f.search(teamA, Query{Entity: EntityTransactions, Filters: Filters{Decisions: []string{"DENY"}}}); r.Empty != EmptyNothingInScope {
		t.Errorf("team A denials: %s", r.Empty)
	}
	if r := f.search(teamA, Query{Entity: EntityTransactions}); r.Empty != "" || !r.Range.Changing {
		t.Errorf("team A: empty %q, range %+v", r.Empty, r.Range)
	}
}

// TestHR257_BuiltinsRunUnderTheViewersScope: production access is the
// production environment's rows the viewer may read, labeled attempts
// until an effect is confirmed.
func TestHR257_BuiltinsRunUnderTheViewersScope(t *testing.T) {
	f := newFx(t)
	teamB := f.caller(td.RoleDeveloper, td.Scope{Type: td.ScopeTeam, ID: f.teamB})
	org := f.caller(td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
	q, _, err := BuiltinQuery{Name: BuiltinProductionAccess}.expand(f.s.now())
	if err != nil {
		t.Fatal(err)
	}
	if r := f.search(teamB, q); r.Count != 0 {
		t.Fatalf("team B sees production access of team A: %d", r.Count)
	}
	r := f.search(org, q)
	if r.Count != 3 || slices.ContainsFunc(r.Items, func(i Item) bool { return i.Label != "ATTEMPT" }) {
		t.Fatalf("org production access: %d %+v", r.Count, r.Items)
	}
}
