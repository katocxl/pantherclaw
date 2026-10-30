// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package cohorts_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/cohorts"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// findingsWorld is the scope world with findings of each kind on both
// agents: an open coverage finding, an active exception and a FAILED
// target of an open rollout, each written as the database admin.
type findingsWorld struct {
	*world
	d                *dbtest.DB
	everyone, onlyA  ids.UUID
	findingsPerAgent int
}

func newFindingsWorld(t *testing.T) *findingsWorld {
	t.Helper()
	d := dbtest.New(t)
	w := newWorldOn(t, d)
	f := &findingsWorld{world: w, d: d, findingsPerAgent: 1}
	admin := w.as(td.RoleFleetManager, nil)
	all, err := w.svc.Create(admin, cohorts.Input{Name: "everyone", Owner: w.owner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.ChangeMembers(admin, all.ID, []ids.UUID{w.a1, w.b1}, false); err != nil {
		t.Fatal(err)
	}
	a, err := w.svc.Create(admin, cohorts.Input{Name: "team-a", Owner: w.owner, Rule: &cohorts.Rule{TeamID: &w.teamA}})
	if err != nil {
		t.Fatal(err)
	}
	f.everyone, f.onlyA = all.ID, a.ID
	policy, version, rollout := ids.NewV7(), ids.NewV7(), ids.NewV7()
	d.AdminExec(t, "INSERT INTO pc.policies (org_id, id, bundle_id) VALUES ($1, $2, 'refunds')", w.org, policy)
	d.AdminExec(t, `INSERT INTO pc.policy_versions (org_id, id, policy_id, version, bundle, state, created_by)
		VALUES ($1, $2, $3, 1, '{"id":"refunds","version":1}', 'DRAFT', 'test')`, w.org, version, policy)
	d.AdminExec(t, `INSERT INTO pc.policy_rollouts (org_id, id, version_id, stage, created_by) VALUES ($1, $2, $3, 'SHADOW', 'test')`,
		w.org, rollout, version)
	for i, agent := range []ids.UUID{w.a1, w.b1} {
		fp := make([]byte, 32)
		fp[0] = byte(i + 1)
		d.AdminExec(t, `INSERT INTO pc.coverage_findings (org_id, id, kind, agent_id, subject, declared, held, used, excess, severity, fingerprint)
			VALUES ($1, $2, 'credential_overreach', $3, 'GitHub App 1', '{}', '{repo}', '{}', '{repo}', 'high', $4)`, w.org, ids.NewV7(), agent, fp)
		d.AdminExec(t, `INSERT INTO pc.policy_rollout_targets (org_id, rollout_id, agent_id, state) VALUES ($1, $2, $3, 'FAILED')`,
			w.org, rollout, agent)
		x := ids.NewV7()
		d.AdminExec(t, `INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations, reason,
			owner_id, requested_by, requested_expiry) VALUES ($1, $2, 'refunds', 'hold', $3, $4, ARRAY['payments.refund.create'], 'why',
			$5, $5, now() + interval '1 day')`, w.org, x, make([]byte, 32), agent, w.owner)
		d.AdminExec(t, "UPDATE pc.policy_exceptions SET state = 'ACTIVE' WHERE id = $1", x)
	}
	return f
}

// TestHR480_FindingsCountEachKindOverTheCohortsAgents: an org reader is
// shown every kind for the cohort's agents; a reader without the
// permission a kind needs is not shown that kind at all.
// Covers: F602
func TestHR480_FindingsCountEachKindOverTheCohortsAgents(t *testing.T) {
	f := newFindingsWorld(t)
	got, err := f.svc.GetFindings(f.as(td.RoleOrgAdmin, nil), f.everyone)
	if err != nil {
		t.Fatal(err)
	}
	if got.Agents != 2 {
		t.Fatalf("%d agents counted, want 2", got.Agents)
	}
	for name, c := range map[string]cohorts.Count{
		"coverage": got.Coverage, "failed targets": got.FailedTargets, "active exceptions": got.ActiveExceptions,
	} {
		if !c.Shown || c.Findings != 2 || c.Agents != 2 {
			t.Errorf("%s: %+v, want 2 on 2 agents", name, c)
		}
	}
	if !got.Departures.Shown || got.Departures.Findings != 0 {
		t.Errorf("departures without a baseline: %+v", got.Departures)
	}
	// A run launcher reads agents, but neither coverage nor policy.
	launcher, err := f.svc.GetFindings(f.as(td.RoleRunLauncher, nil), f.everyone)
	if err != nil {
		t.Fatal(err)
	}
	if launcher.Coverage.Shown || launcher.FailedTargets.Shown || launcher.ActiveExceptions.Shown ||
		launcher.Coverage.Findings+launcher.FailedTargets.Findings+launcher.ActiveExceptions.Findings != 0 {
		t.Errorf("kinds shown without their permission: %+v", launcher)
	}
}

// TestT213_FindingsNeverReachOutsideTheCallersScope: a reader scoped to
// team A cannot read the findings of a cohort that holds team B's agent,
// and the findings of its team's cohort count only team A's agent, though
// team B's agent has findings of every kind. Kinds read at the org are not
// shown to a team reader.
// Covers: F602
func TestT213_FindingsNeverReachOutsideTheCallersScope(t *testing.T) {
	f := newFindingsWorld(t)
	teamA := f.as(td.RoleAgentOwner, &td.Scope{Type: td.ScopeTeam, ID: f.teamA})
	if _, err := f.svc.GetFindings(teamA, f.everyone); !errors.Is(err, cohorts.ErrNotFound) {
		t.Fatalf("a team reader read an org cohort's findings: %v", err)
	}
	got, err := f.svc.GetFindings(teamA, f.onlyA)
	if err != nil {
		t.Fatal(err)
	}
	if got.Agents != 1 {
		t.Errorf("team A's cohort counts %d agents, want only team A's", got.Agents)
	}
	// Each kind needs its read at the org, as the reads it counts do: a
	// team reader is shown none of them.
	if got.Coverage.Shown || got.FailedTargets.Shown || got.ActiveExceptions.Shown {
		t.Errorf("org-level kinds shown to a team reader: %+v", got)
	}
	admin, err := f.svc.GetFindings(f.as(td.RoleOrgAdmin, nil), f.onlyA)
	if err != nil {
		t.Fatal(err)
	}
	if admin.Agents != 1 || admin.Coverage.Findings != 1 || admin.Coverage.Agents != 1 {
		t.Errorf("team A's cohort for an org reader: %d agents, coverage %+v; want team A's agent only", admin.Agents, admin.Coverage)
	}
	if _, err := f.svc.GetFindings(teamA, ids.NewV7()); !errors.Is(err, cohorts.ErrNotFound) {
		t.Errorf("an unknown cohort: %v", err)
	}
}
