// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func graphScope(agent, conn ids.UUID, op string, state domain.State, routes ...app.SnapshotRoute) app.GraphScope {
	return app.GraphScope{
		Scope: domain.Scope{Agent: agent, Connection: conn, Operation: op}, State: state, Routes: routes,
		Target: app.GraphTarget{ID: "api.example.com", Label: "api.example.com"},
	}
}

// TestHR402_TheGraphIsBuiltOnlyFromReadableRecords: a scope the caller may
// not read leaves no node, edge or route behind and does not count towards
// the boundary state, which reads UNKNOWN once anything is hidden or the
// list was cut, so a hidden weaker scope cannot make the agent look
// protected.
//
// Covers: F277
func TestHR402_TheGraphIsBuiltOnlyFromReadableRecords(t *testing.T) {
	agent, conn := ids.NewV7(), ids.NewV7()
	closed := app.SnapshotRoute{Kind: "host", Route: ids.NewV7().String(), Status: "closed", Closure: ids.NewV7().String()}
	mediated := app.SnapshotRoute{Kind: "channel", Channel: "http", Route: ids.NewV7().String(), Status: "mediated"}
	hiddenRoute := app.SnapshotRoute{Kind: "browser", Route: ids.NewV7().String(), Status: "possible"}
	scopes := []app.GraphScope{
		graphScope(agent, conn, "payments.refund.get", domain.Enforced, mediated, closed),
		graphScope(agent, conn, "payments.refund.create", domain.ObserveOnly, hiddenRoute),
	}
	all := func(domain.Scope) bool { return true }
	g := app.AssembleGraph(agent, scopes, all, false)
	if g.ScopeLimited || g.BoundaryState != "PARTIALLY_PROTECTED" {
		t.Fatalf("whole graph: limited %v, boundary %q", g.ScopeLimited, g.BoundaryState)
	}
	notCreate := func(sc domain.Scope) bool { return sc.Operation != "payments.refund.create" }
	g = app.AssembleGraph(agent, scopes, notCreate, false)
	if !g.ScopeLimited || g.BoundaryState != app.BoundaryUnknown {
		t.Fatalf("a hidden scope: limited %v, boundary %q, want UNKNOWN (not PROTECTED)", g.ScopeLimited, g.BoundaryState)
	}
	for _, n := range g.Nodes {
		if strings.Contains(n.ID, "payments.refund.create") || strings.Contains(n.ID, hiddenRoute.Route) || n.Label == "browser" {
			t.Errorf("a node of the hidden scope: %+v", n)
		}
	}
	for _, e := range g.Edges {
		if strings.Contains(e.From+e.To, "payments.refund.create") {
			t.Errorf("an edge of the hidden scope: %+v", e)
		}
	}
	if len(g.Nodes) != 5 || len(g.Edges) != 5 { // agent, scope, two routes, target
		t.Fatalf("nodes %+v edges %+v", g.Nodes, g.Edges)
	}
	if g := app.AssembleGraph(agent, scopes[:1], all, true); !g.ScopeLimited || g.BoundaryState != app.BoundaryUnknown {
		t.Fatalf("a cut list: limited %v, boundary %q", g.ScopeLimited, g.BoundaryState)
	}
	if g := app.AssembleGraph(agent, scopes[:1], all, false); g.BoundaryState != "PROTECTED" {
		t.Fatalf("one enforced scope: %q", g.BoundaryState)
	}
}

// TestHR402_UnknownIsNeverShownAsControlled: only mediated and closed
// routes are TESTED; every status the evidence does not establish is
// UNVERIFIED.
//
// Covers: F277
func TestHR402_UnknownIsNeverShownAsControlled(t *testing.T) {
	for status, want := range map[string]string{
		"mediated": app.ControlTested, "closed": app.ControlTested, "possible": app.ControlPossible, "excluded": app.ControlExcluded,
		"monitored": app.ControlUnverified, "cooperative": app.ControlUnverified, "opaque": app.ControlUnverified,
		"not_observed": app.ControlUnverified, "proposed": app.ControlUnverified, "": app.ControlUnverified, "anything": app.ControlUnverified,
	} {
		if got := app.RouteControl(status); got != want {
			t.Errorf("%q: %s, want %s", status, got, want)
		}
	}
}

// TestF277_TheGraphJoinsAgentScopesRoutesAndTargets: edges run agent to
// scope, scope to route and route to target; a route with no inventory id
// is named by its kind, and each scope keeps its own route node.
//
// Covers: F277
func TestF277_TheGraphJoinsAgentScopesRoutesAndTargets(t *testing.T) {
	agent, conn := ids.NewV7(), ids.NewV7()
	unseen := app.SnapshotRoute{Kind: "git_ssh", Status: "not_observed"}
	g := app.AssembleGraph(agent, []app.GraphScope{
		graphScope(agent, conn, "payments.refund.get", domain.Partial, unseen),
		graphScope(agent, conn, "payments.refund.create", domain.Partial, unseen),
	}, func(domain.Scope) bool { return true }, false)
	root, target := "agent:"+agent.String(), "target:api.example.com"
	for _, op := range []string{"payments.refund.get", "payments.refund.create"} {
		scope := "scope:" + conn.String() + "/" + op
		route := "route:" + conn.String() + "/" + op + "/git_ssh"
		for _, e := range []app.GraphEdge{{From: root, To: scope}, {From: scope, To: route}, {From: route, To: target}} {
			if !slices.Contains(g.Edges, e) {
				t.Errorf("no edge %+v in %+v", e, g.Edges)
			}
		}
		i := slices.IndexFunc(g.Nodes, func(n app.GraphNode) bool { return n.ID == route })
		if i < 0 || g.Nodes[i].Control != app.ControlUnverified || g.Nodes[i].RouteKind != "git_ssh" || g.Nodes[i].Kind != app.NodeRoute {
			t.Errorf("route node %s: %+v", route, g.Nodes)
		}
	}
	if n := len(slices.DeleteFunc(slices.Clone(g.Nodes), func(n app.GraphNode) bool { return n.Kind != app.NodeTarget })); n != 1 {
		t.Errorf("%d target nodes, want 1", n)
	}
	if g.BoundaryState != "OBSERVED" {
		t.Errorf("boundary %q", g.BoundaryState)
	}
}
