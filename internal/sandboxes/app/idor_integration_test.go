// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	"github.com/katocxl/pantherclaw/internal/sandboxes/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestT037_AnotherOrgsSandboxSessionIsNotFound: every SandboxService call
// that names another org's session, agent or connection finds nothing and
// changes nothing there; lists never show it.
func TestT037_AnotherOrgsSandboxSessionIsNotFound(t *testing.T) {
	d := dbtest.New(t)
	w, them := newWorldOn(t, d), newWorldOn(t, d)
	theirs, err := them.svc.StartSession(them.as(td.RoleAgentOwner), them.input())
	if err != nil {
		t.Fatal(err)
	}
	them.admit(t, theirs)
	ctx, id := w.as(td.RoleAgentOwner), theirs.Session.ID

	if _, _, err := w.svc.GetSession(ctx, id); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("get: %v", err)
	}
	if _, err := w.svc.SubmitProbeReport(ctx, id, them.signed(t, theirs, report.KindSandbox, theirs.Nonces.Sandbox, nil), nil); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("a probe report: %v", err)
	}
	if _, err := w.svc.SubmitCanaryReport(ctx, id, them.signed(t, theirs, report.KindCanary, theirs.Nonces.Canary, nil)); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("a canary report: %v", err)
	}
	if _, err := w.svc.ReportRoutes(ctx, id, []app.Route{{Kind: "direct_api", Locator: "pypi.org:443"}}); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("routes: %v", err)
	}
	if _, err := w.svc.EndSession(ctx, id); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("end: %v", err)
	}
	for name, agent := range map[string]*ids.UUID{"all": nil, "their agent": &them.agent} {
		if l, err := w.svc.ListSessions(ctx, agent, nil, 10); err != nil || len(l) != 0 {
			t.Errorf("list %s: %d, %v", name, len(l), err)
		}
	}
	in := w.input()
	in.Agent = them.agent
	if _, err := w.svc.StartSession(ctx, in); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("a session for their agent: %v", err)
	}
	in = w.input()
	in.Connections = []ids.UUID{them.gh}
	if _, err := w.svc.StartSession(ctx, in); !errors.Is(err, app.ErrConnections) {
		t.Errorf("a session mapping their connection: %v", err)
	}

	// Nothing changed in their org.
	if n := them.count(t, "SELECT count(*) FROM pc.sandbox_sessions WHERE id = $1 AND state = 'OPEN'", id); n != 1 {
		t.Error("their session is no longer open")
	}
	if n := them.count(t, "SELECT count(*) FROM pc.probe_nonces WHERE session_id = $1 AND used_at IS NULL", id); n != 3 {
		t.Errorf("%d of their nonces unused, want 3", n)
	}
	if n := them.count(t, "SELECT count(*) FROM pc.coverage_routes WHERE agent_id = $1", them.agent); n != 0 {
		t.Errorf("%d routes recorded for their agent", n)
	}
}
