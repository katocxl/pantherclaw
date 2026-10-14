// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandboxes/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR148_RoutesTheEdgeSawAreUntrustedObservedRoutes: what the edge saw
// the agent take becomes observed routes (source probe) of the agent and
// each mapped connection, once each; a first sighting makes coverage
// recompute the scope, and nothing else changes. Only a launcher of an
// open session reports them, and every route is bounded and printable.
func TestHR148_RoutesTheEdgeSawAreUntrustedObservedRoutes(t *testing.T) {
	w := newWorld(t)
	second := ids.NewV7()
	w.connection(t, second, "github-uploads", w.gateway, []string{"uploads.github.com"})
	in := w.input()
	in.Connections = append(in.Connections, second)
	ctx := w.as(td.RoleAgentOwner)
	s, err := w.svc.StartSession(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	routes := []app.Route{{Kind: "direct_api", Locator: "pypi.org:443"}, {Kind: "credential", Locator: "github_pat:0a1b2c3d4e5f"}}
	if n, err := w.svc.ReportRoutes(ctx, s.Session.ID, routes); err != nil || n != 4 {
		t.Fatalf("first report: %d new, %v", n, err)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.coverage_routes WHERE agent_id = $1 AND source = 'probe' AND observation = 'observed'
		AND source_ref = $2`, w.agent, s.Session.ID); n != 4 {
		t.Fatalf("%d observed routes stored", n)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.coverage_invalidations WHERE kind = 'route' AND agent_id = $1", w.agent); n != 4 {
		t.Fatalf("%d route changes", n)
	}
	if n, err := w.svc.ReportRoutes(ctx, s.Session.ID, routes[:1]); err != nil || n != 0 {
		t.Fatalf("seen again: %d new, %v", n, err)
	}

	for name, rs := range map[string][]app.Route{
		"none":             nil,
		"another kind":     {{Kind: "host", Locator: "docker.sock"}},
		"a control char":   {{Kind: "direct_api", Locator: "evil\n.example:443"}},
		"a long locator":   {{Kind: "direct_api", Locator: strings.Repeat("a", 513)}},
		"over the maximum": make([]app.Route, app.MaxRoutes+1),
	} {
		if _, err := w.svc.ReportRoutes(ctx, s.Session.ID, rs); !errors.Is(err, app.ErrRoutes) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := w.svc.ReportRoutes(w.as(td.RoleViewer), s.Session.ID, routes); err == nil {
		t.Error("a viewer reported routes")
	}
	if _, err := w.svc.ReportRoutes(ctx, ids.NewV7(), routes); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("an unknown session: %v", err)
	}
	if _, err := w.svc.EndSession(ctx, s.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.ReportRoutes(ctx, s.Session.ID, routes); !errors.Is(err, app.ErrNotOpen) {
		t.Errorf("an ended session: %v", err)
	}
}
