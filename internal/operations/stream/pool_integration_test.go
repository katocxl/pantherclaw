// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package stream_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/operations/stream"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR256_TheStreamScopesViewersByEachPermissionWhereAgentsLive: a team
// viewer's stream scope holds its team's agent only; an org-wide viewer's
// holds all; the feed of an empty org starts at 0.
func TestHR256_TheStreamScopesViewersByEachPermissionWhereAgentsLive(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	org, user := ids.New[ids.Org](), ids.NewV7()
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", org, user)
	agents := map[string]ids.UUID{}
	teams := map[string]ids.UUID{}
	for _, slug := range []string{"alpha", "bravo"} {
		team, env, agent := ids.NewV7(), ids.NewV7(), ids.NewV7()
		exec("INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, $3, $3)", org, team, slug)
		exec("INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, $4, $4, 'DEVELOPMENT')",
			org, env, team, slug+"-env")
		exec(`INSERT INTO pc.agents (org_id, id, name, state, team_id, environment_id, owner_user_id, execution_context,
			claimed_at, created_by) VALUES ($1, $2, $3, 'CLAIMED', $4, $5, $6, 'ci', now(), 'test')`, org, agent, slug, team, env, user)
		agents[slug], teams[slug] = agent, team
	}
	caller := func(role td.RoleName, s td.Scope) tenancy.Caller {
		return tenancy.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
			Bindings: []td.Binding{{Role: role, Scope: s}},
		}}
	}
	sc, err := stream.PoolScoper{Pool: p}.Scope(ctx, caller(td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: teams["alpha"]}), td.PermIncidentRead)
	if err != nil {
		t.Fatal(err)
	}
	if sc.All || len(sc.Agents) != 1 || !sc.Agents[agents["alpha"]] {
		t.Fatalf("team scope: %+v", sc)
	}
	sc, err = stream.PoolScoper{Pool: p}.Scope(ctx, caller(td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: org.UUID()}), td.PermIncidentRead)
	if err != nil || !sc.All {
		t.Fatalf("org scope: %+v %v", sc, err)
	}
	f := stream.PoolFeed{Pool: p}
	if head, err := f.Head(ctx, org); err != nil || head != 0 {
		t.Fatalf("head: %d %v", head, err)
	}
	if evs, err := f.After(ctx, org, 0, 500); err != nil || len(evs) != 0 {
		t.Fatalf("after: %d %v", len(evs), err)
	}
}
