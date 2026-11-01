// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type fakeEnts struct{ edition billing.Edition }

func (f *fakeEnts) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	if f.edition != "" {
		e.Edition, e.Limits.MaxAgents = f.edition, billing.Unlimited
	}
	return e, nil
}

type world struct {
	pool                 *db.Pool
	inv                  *app.Inventory
	ents                 *fakeEnts
	org                  ids.OrgID
	team, team2, env     ids.UUID
	owner, backup, other ids.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	p := dbtest.New(t).AppPool(t)
	w := &world{pool: p, ents: &fakeEnts{edition: billing.Business}}
	w.inv = app.NewInventory(p, w.ents)
	w.org = w.newOrg(t)
	return w
}

// newOrg creates an org with two teams, an environment of the first team
// and three users, and points the world at it.
func (w *world) newOrg(t *testing.T) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	w.team, w.team2, w.env = ids.NewV7(), ids.NewV7(), ids.NewV7()
	w.owner, w.backup, w.other = ids.NewV7(), ids.NewV7(), ids.NewV7()
	w.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	w.exec(t, org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng'), ($1, $3, 'ops', 'Ops')", org, w.team, w.team2)
	w.exec(t, org, `INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')`, org, w.env, w.team)
	for i, u := range []ids.UUID{w.owner, w.backup, w.other} {
		w.exec(t, org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)",
			org, u, []string{"alice", "bob", "carol"}[i])
	}
	return org
}

func (w *world) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	if err := w.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func as(org ids.OrgID, kind td.PrincipalKind, bs ...td.Binding) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject:    td.Subject{Org: org, Principal: td.PrincipalRef{Kind: kind, ID: ids.NewV7()}, Bindings: bs},
		Credential: tenancy.CredAccessToken,
	})
}

func bind(r td.RoleName, t td.ScopeType, id ids.UUID) td.Binding {
	return td.Binding{Role: r, Scope: td.Scope{Type: t, ID: id}}
}

func (w *world) teamOwner() context.Context {
	return as(w.org, td.KindUser, bind(td.RoleAgentOwner, td.ScopeTeam, w.team))
}

func (w *world) details() domain.Details {
	return domain.Details{
		Name: "Claude Code, engineering", Purpose: "Writes code", TeamID: w.team, EnvironmentID: w.env,
		OwnerUserID: w.owner, BackupOwnerUserID: w.backup, Context: domain.ContextCI,
	}
}

func wantCode(t *testing.T, what string, err error, code pcerr.Code, reason string) {
	t.Helper()
	if pcerr.CodeOf(err) != code || (reason != "" && pcerr.ReasonOf(err) != reason) {
		t.Errorf("%s: err = %v, want %s %s", what, err, code, reason)
	}
}

func TestIntAgentInventory(t *testing.T) {
	w := newWorld(t)
	ctx := w.teamOwner()
	a, err := w.inv.Create(ctx, w.details())
	if err != nil {
		t.Fatal(err)
	}
	if a.State != domain.StateClaimed || a.OwnerUserID != w.owner || a.ClaimedAt == nil {
		t.Fatalf("created %+v", a)
	}
	s, err := w.inv.Get(ctx, a.ID)
	if err != nil || s.Activity != domain.ActivityNoInstances || s.NextAction == "" || s.Discovery != nil {
		t.Fatalf("summary %+v, %v", s, err)
	}
	name := "Claude Code, platform"
	if _, err := w.inv.Update(ctx, a.ID, &name, nil, domain.RiskPatch{}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.inv.TransferOwnership(ctx, a.ID, w.other, ids.UUID{}, "alice moved teams"); err != nil {
		t.Fatal(err)
	}
	l, none, err := w.inv.List(ctx, page.Request{Size: 10}, nil, ids.UUID{})
	if err != nil || none || len(l.Items) != 1 || l.Items[0].Name != name || l.Items[0].OwnerUserID != w.other {
		t.Fatalf("list %+v none=%v err=%v", l, none, err)
	}
	h, err := w.inv.ListChanges(ctx, a.ID, page.Request{Size: 10})
	if err != nil || len(h.Items) != 3 || h.Items[0].Kind != string(domain.ChangeCreated) ||
		h.Items[2].Kind != string(domain.ChangeOwnershipTransferred) || h.Items[2].Reason != "alice moved teams" {
		t.Fatalf("history %+v, %v", h, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE 'audit.agents.%'", w.org); n != 3 {
		t.Fatalf("audit entries %d", n)
	}
	// F624: an empty org says so; an empty filter result does not.
	other := newWorld(t)
	if _, none, _ := other.inv.List(other.teamOwner(), page.Request{Size: 10}, nil, ids.UUID{}); !none {
		t.Error("an org without agents must report it")
	}
	if _, none, _ := w.inv.List(ctx, page.Request{Size: 10}, []domain.State{domain.StateRetired}, ids.UUID{}); none {
		t.Error("a filter with no match is not an empty org")
	}
}

// TestT037_AgentIDOR: another org's ids are NotFound for every use case.
func TestT037_AgentIDOR(t *testing.T) {
	w := newWorld(t)
	a, err := w.inv.Create(w.teamOwner(), w.details())
	if err != nil {
		t.Fatal(err)
	}
	stranger := as(ids.New[ids.Org](), td.KindUser, bind(td.RoleOrgAdmin, td.ScopeOrg, ids.NewV7()))
	name := "x"
	for what, call := range map[string]func() error{
		"get":      func() error { _, err := w.inv.Get(stranger, a.ID); return err },
		"update":   func() error { _, err := w.inv.Update(stranger, a.ID, &name, nil, domain.RiskPatch{}); return err },
		"transfer": func() error { _, err := w.inv.TransferOwnership(stranger, a.ID, w.owner, ids.UUID{}, "r"); return err },
		"suspend":  func() error { _, err := w.inv.Suspend(stranger, a.ID, "r"); return err },
		"retire":   func() error { _, err := w.inv.Retire(stranger, a.ID, "r"); return err },
		"history":  func() error { _, err := w.inv.ListChanges(stranger, a.ID, page.Request{Size: 1}); return err },
		"claim":    func() error { _, err := w.inv.Claim(stranger, a.ID, nil, a.ID, "r"); return err },
	} {
		wantCode(t, what, call(), pcerr.NotFound, "")
	}
}

func TestIntAgentPermissionsAndPlacement(t *testing.T) {
	w := newWorld(t)
	dev := as(w.org, td.KindUser, bind(td.RoleDeveloper, td.ScopeTeam, w.team))
	_, err := w.inv.Create(dev, w.details())
	wantCode(t, "developer creates", err, pcerr.PermissionDenied, "")
	elsewhere := as(w.org, td.KindUser, bind(td.RoleAgentOwner, td.ScopeTeam, w.team2))
	_, err = w.inv.Create(elsewhere, w.details())
	wantCode(t, "owner of another team creates", err, pcerr.PermissionDenied, "")
	a, err := w.inv.Create(w.teamOwner(), w.details())
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.inv.Get(elsewhere, a.ID)
	wantCode(t, "owner of another team reads", err, pcerr.PermissionDenied, "")
	if _, err := w.inv.Get(dev, a.ID); err != nil {
		t.Errorf("developer reads: %v", err)
	}
	d := w.details()
	d.TeamID = w.team2 // the environment belongs to the first team
	_, err = w.inv.Create(as(w.org, td.KindUser, bind(td.RoleOrgAdmin, td.ScopeOrg, w.org.UUID()), bind(td.RoleAgentOwner, td.ScopeOrg, w.org.UUID())), d)
	wantCode(t, "environment of another team", err, pcerr.InvalidArgument, "AGENT_PLACEMENT")
	w.exec(t, w.org, "UPDATE pc.users SET state = 'DISABLED' WHERE org_id = $1 AND id = $2", w.org, w.backup)
	_, err = w.inv.Create(w.teamOwner(), w.details())
	wantCode(t, "disabled backup owner", err, pcerr.InvalidArgument, "AGENT_OWNER")
	_, err = w.inv.TransferOwnership(w.teamOwner(), a.ID, w.owner, w.owner, "same person")
	wantCode(t, "owner is backup", err, pcerr.InvalidArgument, "AGENT_OWNER")
}

func TestIntAgentEditionLimit(t *testing.T) {
	w := newWorld(t)
	w.ents.edition = "" // Community: 5 governed agents
	ctx := w.teamOwner()
	var first app.Agent
	for i := range 5 {
		a, err := w.inv.Create(ctx, w.details())
		if err != nil {
			t.Fatalf("agent %d: %v", i, err)
		}
		if i == 0 {
			first = a
		}
	}
	_, err := w.inv.Create(ctx, w.details())
	wantCode(t, "sixth agent", err, pcerr.FailedPrecondition, "AGENT_LIMIT")
	if _, err := w.inv.Retire(ctx, first.ID, "frees a slot"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.inv.Create(ctx, w.details()); err != nil {
		t.Fatalf("after retiring one: %v", err)
	}
}

// TestRace_AgentLimitHoldsUnderConcurrentCreates: the org's limit lock lets
// exactly the allowed number through.
func TestRace_AgentLimitHoldsUnderConcurrentCreates(t *testing.T) {
	w := newWorld(t)
	w.ents.edition = ""
	ctx := w.teamOwner()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.inv.Create(ctx, w.details()); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 5 {
		t.Fatalf("%d agents created, want 5", ok)
	}
}

func epoch(t *testing.T, w *world) int {
	return w.count(t, "SELECT coalesce((SELECT epoch FROM pc.org_containment WHERE org_id = $1), 0)::int", w.org)
}

// TestHR002_SuspendAndRetireMoveTheContainmentEpoch, and retirement revokes
// everything the agent holds (F023).
func TestHR002_SuspendAndRetireMoveTheContainmentEpoch(t *testing.T) {
	w := newWorld(t)
	ctx := w.teamOwner()
	a, _ := w.inv.Create(ctx, w.details())
	before := epoch(t, w)
	s, err := w.inv.Suspend(ctx, a.ID, "suspicious pushes")
	if err != nil || s.State != domain.StateSuspended || s.SuspendedFrom != domain.StateClaimed || epoch(t, w) <= before {
		t.Fatalf("suspend: %+v, %v (epoch %d → %d)", s, err, before, epoch(t, w))
	}
	_, err = w.inv.Suspend(ctx, a.ID, "again")
	wantCode(t, "suspend twice", err, pcerr.FailedPrecondition, "AGENT_STATE")
	inst, run := ids.NewV7(), ids.NewV7()
	w.exec(t, w.org, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFG', '{}', 'PENDING_ADMISSION', 'discovery')`, w.org, inst, a.ID)
	w.exec(t, w.org, `INSERT INTO pc.enrollment_tokens (org_id, id, agent_id, environment_id, token_hash, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'test', now() + interval '10 minutes')`, w.org, ids.NewV7(), a.ID, w.env, make([]byte, 32))
	w.exec(t, w.org, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id,
		principal_source, expires_at) VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '1 hour')`, w.org, run, a.ID, w.env, w.owner)
	w.exec(t, w.org, `INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, deadline_at)
		VALUES ($1, $2, 'ADMISSION', 'instance', $3, $4, now() + interval '7 days')`, w.org, ids.NewV7(), inst, a.ID)
	mid := epoch(t, w)
	r, err := w.inv.Retire(ctx, a.ID, "replaced")
	if err != nil || r.State != domain.StateRetired || r.RetiredAt == nil || epoch(t, w) <= mid {
		t.Fatalf("retire: %+v, %v", r, err)
	}
	for what, sql := range map[string]string{
		"instances": "SELECT count(*) FROM pc.agent_instances WHERE org_id = $1 AND state <> 'REVOKED'",
		"tokens":    "SELECT count(*) FROM pc.enrollment_tokens WHERE org_id = $1 AND state <> 'REVOKED'",
		"runs":      "SELECT count(*) FROM pc.runs WHERE org_id = $1 AND state <> 'REVOKED'",
		"entries":   "SELECT count(*) FROM pc.waitlist_entries WHERE org_id = $1 AND state = 'OPEN'",
	} {
		if n := w.count(t, sql, w.org); n != 0 {
			t.Errorf("%s still live after retirement: %d", what, n)
		}
	}
	name := "back"
	_, err = w.inv.Update(ctx, a.ID, &name, nil, domain.RiskPatch{})
	wantCode(t, "update a retired agent", err, pcerr.FailedPrecondition, "AGENT_STATE")
	_, err = w.inv.Suspend(ctx, a.ID, "x")
	wantCode(t, "suspend a retired agent", err, pcerr.FailedPrecondition, "AGENT_STATE")
}

// TestHR004_ConcurrentSuspendHasOneWinner.
func TestHR004_ConcurrentSuspendHasOneWinner(t *testing.T) {
	w := newWorld(t)
	ctx := w.teamOwner()
	a, _ := w.inv.Create(ctx, w.details())
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() { defer wg.Done(); _, errs[i] = w.inv.Suspend(ctx, a.ID, "race") }()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d suspensions succeeded, want 1 (%v)", ok, errs)
	}
}

func (w *world) discovered(t *testing.T, key string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	w.exec(t, w.org, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'discovered', 'DISCOVERED', 'system')", w.org, id)
	w.exec(t, w.org, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, key_jkt, public_jwk, observed)
		VALUES ($1, $2, $3, 'gateway', $4, '{}', '{"user_agent":"curl/8"}')`, w.org, ids.NewV7(), id, key)
	w.exec(t, w.org, `INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, deadline_at)
		VALUES ($1, $2, 'ADMISSION', 'agent', $3, $3, now() + interval '7 days')`, w.org, ids.NewV7(), id)
	return id
}

// TestIntClaimAndMergeDiscoveredAgents (F015, F035): claiming resolves the
// ADMISSION entry and grants nothing; merging moves the discovery and
// retires the discovered record.
func TestIntClaimAndMergeDiscoveredAgents(t *testing.T) {
	w := newWorld(t)
	orgOwner := as(w.org, td.KindUser, bind(td.RoleAgentOwner, td.ScopeOrg, w.org.UUID()))
	d1 := w.discovered(t, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	s, err := w.inv.Get(orgOwner, d1)
	if err != nil || s.Discovery == nil || s.Discovery.Observed["user_agent"] != "curl/8" || s.State != domain.StateDiscovered {
		t.Fatalf("discovered summary %+v, %v", s, err)
	}
	det := w.details()
	a, err := w.inv.Claim(orgOwner, d1, &det, ids.UUID{}, "our CI agent")
	if err != nil || a.ID != d1 || a.State != domain.StateClaimed || a.Context != domain.ContextCI {
		t.Fatalf("claim: %+v, %v", a, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.waitlist_entries WHERE org_id = $1 AND state = 'APPROVED'", w.org); n != 1 {
		t.Errorf("admission entries approved: %d", n)
	}
	_, err = w.inv.Claim(orgOwner, d1, &det, ids.UUID{}, "again")
	wantCode(t, "claim twice", err, pcerr.FailedPrecondition, "AGENT_STATE")
	d2 := w.discovered(t, "1123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	m, err := w.inv.Claim(orgOwner, d2, nil, a.ID, "same agent, second key")
	if err != nil || m.ID != a.ID {
		t.Fatalf("merge: %+v, %v", m, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.discoveries WHERE org_id = $1 AND agent_id = $2", w.org, a.ID); n != 2 {
		t.Errorf("discoveries on the merged agent: %d", n)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.agents WHERE org_id = $1 AND id = $2 AND state = 'RETIRED'", w.org, d2); n != 1 {
		t.Error("the merged discovered record was not retired")
	}
	d3 := w.discovered(t, "2123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	_, err = w.inv.Claim(orgOwner, d3, nil, d3, "self")
	wantCode(t, "merge into itself", err, pcerr.InvalidArgument, "CLAIM_TARGET")
	_, err = w.inv.Claim(orgOwner, d3, &det, a.ID, "both")
	wantCode(t, "both targets", err, pcerr.InvalidArgument, "CLAIM_TARGET")
	if _, err := w.inv.Retire(orgOwner, d3, "not ours"); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.discoveries WHERE org_id = $1 AND agent_id = $2 AND state = 'DISMISSED'", w.org, d3); n != 1 {
		t.Error("retiring a discovered agent must dismiss its discovery")
	}
}

// TestHR147_ReusedNameInheritsNothing: a new agent with a retired agent's
// name is a new identity with no runs, instances or history of the old one.
func TestHR147_ReusedNameInheritsNothing(t *testing.T) {
	w := newWorld(t)
	ctx := w.teamOwner()
	old, _ := w.inv.Create(ctx, w.details())
	w.exec(t, w.org, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id,
		principal_source, expires_at) VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '1 hour')`, w.org, ids.NewV7(), old.ID, w.env, w.owner)
	if _, err := w.inv.Retire(ctx, old.ID, "rebuilt"); err != nil {
		t.Fatal(err)
	}
	fresh, err := w.inv.Create(ctx, w.details())
	if err != nil || fresh.ID == old.ID || fresh.Name != old.Name {
		t.Fatalf("fresh %+v, %v", fresh, err)
	}
	s, _ := w.inv.Get(ctx, fresh.ID)
	h, _ := w.inv.ListChanges(ctx, fresh.ID, page.Request{Size: 10})
	if s.ActiveRuns != 0 || s.AdmittedInstances != 0 || len(h.Items) != 1 {
		t.Fatalf("the reused name inherited state: %+v, %d changes", s, len(h.Items))
	}
}
