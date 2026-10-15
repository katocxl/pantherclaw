// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package operations_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fx is an org with two teams and an agent in each.
type fx struct {
	t              *testing.T
	d              *dbtest.DB
	p              *db.Pool
	s              *operations.Service
	org            ids.OrgID
	teamA, teamB   ids.UUID
	agentA, agentB ids.UUID
	user           ids.UUID
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

func (f *fx) agent(team ids.UUID, slug string) ids.UUID {
	agent, env := ids.NewV7(), ids.NewV7()
	f.exec("INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, $3, $3)", f.org, team, slug)
	f.exec("INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, $4, $4, 'PRODUCTION')",
		f.org, env, team, slug+"-env")
	f.exec(`INSERT INTO pc.agents (org_id, id, name, state, team_id, environment_id, owner_user_id, execution_context,
		claimed_at, created_by) VALUES ($1, $2, $3, 'CLAIMED', $4, $5, $6, 'ci', now(), 'test')`, f.org, agent, slug, team, env, f.user)
	return agent
}

func newFx(t *testing.T) *fx {
	t.Helper()
	d := dbtest.New(t)
	f := &fx{t: t, d: d, p: d.AppPool(t), org: ids.New[ids.Org](), teamA: ids.NewV7(), teamB: ids.NewV7(), user: ids.NewV7()}
	f.s = &operations.Service{Pool: f.p}
	f.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", f.org)
	f.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.user)
	f.agentA, f.agentB = f.agent(f.teamA, "alpha"), f.agent(f.teamB, "bravo")
	return f
}

func (f *fx) as(role td.RoleName, scope td.Scope) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.user},
		Bindings: []td.Binding{{Role: role, Scope: scope}},
	}})
}

func (f *fx) orgWide() context.Context {
	return f.as(td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
}

func (f *fx) teamOf(team ids.UUID) context.Context {
	return f.as(td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: team})
}

// incident opens an incident with one alert about agent.
func (f *fx) incident(agent ids.UUID, severity string) ids.UUID {
	inc := ids.NewV7()
	f.exec(`INSERT INTO pc.incidents (org_id, id, title, severity, opened_by) VALUES ($1, $2, 'self-issued grant', $3, 'alert:x')`,
		f.org, inc, severity)
	f.exec(`INSERT INTO pc.alerts (org_id, id, source, title, severity, attention, basis, subjects, dedupe_key, first_seen,
		last_seen, incident_id) VALUES ($1, $2, 'detection', 'self-issued grant', $3, 'INCIDENT', 'RULE_MATCH',
		jsonb_build_array(jsonb_build_object('type', 'agent', 'id', $4::text)), $5, now(), now(), $6)`,
		f.org, ids.NewV7(), severity, agent.String(), ids.NewV7().String(), inc)
	return inc
}

func kinds(q operations.Queue) []string {
	var out []string
	for _, it := range q.Items {
		out = append(out, string(it.Kind)+":"+it.ID)
	}
	return out
}

// TestT112_AnotherTeamsItemsAreNeitherShownNorCounted: an incident about
// team B's agent appears in the org-wide viewer's queue and summary only;
// the team A viewer neither sees it nor counts it, and its summary says
// that agents outside its scope are not counted (HR-258, D8).
func TestT112_AnotherTeamsItemsAreNeitherShownNorCounted(t *testing.T) {
	f := newFx(t)
	incA := f.incident(f.agentA, "HIGH")
	incB := f.incident(f.agentB, "CRITICAL")

	all, err := f.s.GetWorkQueue(f.orgWide())
	if err != nil {
		t.Fatal(err)
	}
	if got := kinds(all); !slices.Contains(got, "INCIDENT:"+incA.String()) || !slices.Contains(got, "INCIDENT:"+incB.String()) || !all.Whole {
		t.Fatalf("org-wide queue: %v", got)
	}
	if all.Items[0].ID != incB.String() {
		t.Fatalf("critical incident not ranked first: %v", kinds(all))
	}
	team, err := f.s.GetWorkQueue(f.teamOf(f.teamA))
	if err != nil {
		t.Fatal(err)
	}
	if got := kinds(team); slices.Contains(got, "INCIDENT:"+incB.String()) || !slices.Contains(got, "INCIDENT:"+incA.String()) || team.Whole {
		t.Fatalf("team A queue: %v", got)
	}
	// The responder may assign its own team's incident.
	for _, it := range team.Items {
		if it.ID == incA.String() && !slices.ContainsFunc(it.Actions, func(a operations.Action) bool { return a.Name == "assign" }) {
			t.Fatalf("team A incident actions: %+v", it.Actions)
		}
	}
	sum, err := f.s.GetSummary(f.teamOf(f.teamA))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Counts[operations.CountActiveIncidents] != 1 || sum.Counts[operations.CountCritical] != 0 {
		t.Fatalf("team A summary counts hidden rows: %v", sum.Counts)
	}
	if !slices.Contains(sum.Unknown, "agents outside your scope are not counted") {
		t.Fatalf("team A summary unknowns: %v", sum.Unknown)
	}
	sum, err = f.s.GetSummary(f.orgWide())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Counts[operations.CountActiveIncidents] != 2 || sum.Counts[operations.CountCritical] != 1 {
		t.Fatalf("org summary: %v", sum.Counts)
	}
}

// TestHR258_TheSummaryIsStampedAndNeverClaimsSafety: even with nothing
// open, the summary names its scope and as-of time, lists what it does not
// know, and says its counts are no statement that nothing is wrong.
func TestHR258_TheSummaryIsStampedAndNeverClaimsSafety(t *testing.T) {
	f := newFx(t)
	sum, err := f.s.GetSummary(f.orgWide())
	if err != nil {
		t.Fatal(err)
	}
	if sum.AsOf.IsZero() || sum.Scope != "the whole organization" || !sum.Whole {
		t.Fatalf("summary stamp: %+v", sum)
	}
	for _, bad := range []string{"no critical issues", "no issues", "all clear", "safe"} {
		if strings.Contains(strings.ToLower(sum.Statement), bad) && !strings.Contains(sum.Statement, "not a statement that nothing is wrong") {
			t.Fatalf("summary claims safety: %q", sum.Statement)
		}
	}
	if !strings.Contains(sum.Statement, "not a statement that nothing is wrong") || !strings.Contains(sum.Statement, sum.AsOf.Format("2006-01-02")) {
		t.Fatalf("statement: %q", sum.Statement)
	}
	if len(sum.Unknown) == 0 {
		t.Fatal("summary lists nothing unknown with no telemetry at all")
	}
}

// TestHR258_MissingTelemetryShowsAsAGapWithItsLastSeenTime: a gateway not
// seen for more than a day is STALE with its last-seen time, one never
// seen is NEVER, and both are gaps that rank in the queue; a team viewer
// gets org-wide sources as RESTRICTED, not as quiet.
func TestHR258_MissingTelemetryShowsAsAGapWithItsLastSeenTime(t *testing.T) {
	f := newFx(t)
	old, fresh := ids.NewV7(), ids.NewV7()
	f.exec("INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge-old', 'test')", f.org, old)
	f.exec("INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge-new', 'test')", f.org, fresh)
	f.d.AdminExec(t, `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, not_before,
		not_after, issued_at) VALUES ($1, $2, $3, '\x01', repeat('a', 43), 'ENROLL', now() - interval '30 hours',
		now() - interval '6 hours', now() - interval '30 hours')`, f.org, ids.NewV7(), old)
	es, err := f.s.GetEvidenceStatus(f.orgWide())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]operations.SourceStatus{}
	for _, s := range es.Sources {
		byName[s.Kind+"/"+s.Name] = s
	}
	if s := byName["gateway/edge-old"]; s.Freshness != operations.Stale || s.LastSeen == nil || !s.Gap() {
		t.Fatalf("old gateway: %+v", s)
	}
	if s := byName["gateway/edge-new"]; s.Freshness != operations.Never || s.LastSeen != nil || !s.Gap() {
		t.Fatalf("new gateway: %+v", s)
	}
	q, err := f.s.GetWorkQueue(f.orgWide())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(q.Items, func(it operations.Item) bool {
		return it.Kind == operations.KindProtectionFailure && strings.Contains(it.Title, "edge-old not seen since")
	}) {
		t.Fatalf("stale gateway not queued: %v", kinds(q))
	}
	es, err = f.s.GetEvidenceStatus(f.teamOf(f.teamA))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range es.Sources {
		if s.Kind == operations.SourceGateway && s.Freshness != operations.Restricted {
			t.Fatalf("team viewer gateway source: %+v", s)
		}
	}
}

// TestOperations_NeedsOperationsRead: a caller without operations.read is
// refused.
func TestOperations_NeedsOperationsRead(t *testing.T) {
	f := newFx(t)
	ctx := f.as(td.RoleDeveloper, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
	if _, err := f.s.GetWorkQueue(ctx); err == nil {
		t.Fatal("queue without operations.read")
	}
	if _, err := f.s.GetSummary(ctx); err == nil {
		t.Fatal("summary without operations.read")
	}
}
