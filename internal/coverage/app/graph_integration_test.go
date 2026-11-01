// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// TestIntCoverageGraphIsTeamAndAboveAndReadsTheAgentsScopes: without a
// licence or on Community the graph answers EDITION_REQUIRED; on Team a
// holder of coverage.read gets the agent, its scope, each route with its
// control and the connection's host, and a viewer gets nothing.
//
// Covers: F277
func TestIntCoverageGraphIsTeamAndAboveAndReadsTheAgentsScopes(t *testing.T) {
	f := newFixture(t)
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'OK',
		'gw', $6, 'http', 'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), f.conn)
	f.reassessOrg(t)
	auditor := f.as(td.RoleAuditor)
	for _, ents := range []app.Entitlements{nil, edition(billing.Community)} {
		f.svc.Ents = ents
		if _, err := f.svc.GetCoverageGraph(auditor, f.agent, app.GraphFilter{}); !errors.Is(err, app.ErrEdition) {
			t.Fatalf("edition %v: %v", ents, err)
		}
	}
	f.svc.Ents = edition(billing.Team)
	g, err := f.svc.GetCoverageGraph(auditor, f.agent, app.GraphFilter{Connection: &f.conn})
	if err != nil || g.ScopeLimited || g.BoundaryState != "OBSERVED" {
		t.Fatalf("graph %+v (%v)", g, err)
	}
	scope := "scope:" + f.conn.String() + "/payments.refund.create"
	has := func(id string) bool {
		return slices.ContainsFunc(g.Nodes, func(n app.GraphNode) bool { return n.ID == id })
	}
	if !has("agent:"+f.agent.String()) || !has(scope) || !has("target:api.example.com") {
		t.Fatalf("nodes %+v", g.Nodes)
	}
	for _, n := range g.Nodes {
		if n.Kind == app.NodeRoute && n.Control != app.RouteControl(n.RouteStatus) {
			t.Errorf("route %+v", n)
		}
	}
	if !slices.ContainsFunc(g.Nodes, func(n app.GraphNode) bool { return n.Kind == app.NodeRoute && n.RouteKind == "target_side" }) {
		t.Errorf("no target-side route: %+v", g.Nodes)
	}
	// Each edge says why, when it was checked and when that stops holding
	// (F278); a scope names the effect group it belongs to (F277).
	for _, n := range g.Nodes {
		if n.Kind == app.NodeScope && n.EffectGroup != "payments.refund.create" {
			t.Errorf("scope without its effect group: %+v", n)
		}
	}
	for _, e := range g.Edges {
		if e.Reason == "" || e.CheckedAt == nil || e.CheckedAt.IsZero() {
			t.Errorf("edge with no reason or check time: %+v", e)
		}
	}
	op := "payments.refund.get"
	if g, err := f.svc.GetCoverageGraph(auditor, f.agent, app.GraphFilter{Operation: &op}); err != nil || len(g.Nodes) != 1 {
		t.Fatalf("another operation: %+v (%v)", g, err)
	}
	if _, err := f.svc.GetCoverageGraph(f.as(td.RoleViewer), f.agent, app.GraphFilter{}); err == nil {
		t.Fatal("a viewer read the graph")
	}
}

// TestIntAGraphFilteredByOperationIsNotCutByOtherOperations: the operation
// filter applies in the query, before the scope cap, so a page of one row
// filtered by an operation holds that operation's scope even when another
// scope sorts first, and the filtered graph is not scope-limited.
//
// Covers: F277
func TestIntAGraphFilteredByOperationIsNotCutByOtherOperations(t *testing.T) {
	f := newFixture(t)
	for _, op := range []string{"payments.refund.create", "payments.refund.get"} {
		f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $7, 'ALLOW', 'OK',
			'gw', $6, 'http', 'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), f.conn, op)
	}
	f.reassessOrg(t)
	op := "payments.refund.get"
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		params := dbq.ListCurrentCoverageSnapshotsPageParams{OrgID: f.org, AgentID: &f.agent, MaxRows: 1}
		first, err := dbq.New(tx).ListCurrentCoverageSnapshotsPage(ctx, params)
		if err != nil || len(first) != 1 || first[0].Operation != "payments.refund.create" {
			t.Fatalf("unfiltered first page %+v (%v)", first, err)
		}
		params.Operation = &op
		got, err := dbq.New(tx).ListCurrentCoverageSnapshotsPage(ctx, params)
		if err != nil || len(got) != 1 || got[0].Operation != op {
			t.Fatalf("filtered page %+v (%v)", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.svc.Ents = edition(billing.Team)
	g, err := f.svc.GetCoverageGraph(f.as(td.RoleAuditor), f.agent, app.GraphFilter{Operation: &op})
	if err != nil || g.ScopeLimited {
		t.Fatalf("graph %+v (%v)", g, err)
	}
	for _, n := range g.Nodes {
		if n.Kind == app.NodeScope && n.Label != op {
			t.Errorf("a scope of another operation: %+v", n)
		}
	}
	if !slices.ContainsFunc(g.Nodes, func(n app.GraphNode) bool { return n.ID == "scope:"+f.conn.String()+"/"+op }) {
		t.Fatalf("no %s scope: %+v", op, g.Nodes)
	}
}
