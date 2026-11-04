// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stream_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/operations/stream"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR655_TheStreamIgnoresTheInvestigatorRole (G0 M27 D510): the role
// counts on its five reads only, so on the live stream a service account
// keeps just its other bindings. With Investigator alone it is refused; with
// Investigator at the org and Viewer in team A it sees team A's alerts and
// not team B's, which the role's org-wide incident.read would have shown.
// Covers: F946
func TestHR655_TheStreamIgnoresTheInvestigatorRole(t *testing.T) {
	w := newWorld(t, stream.Config{Recheck: 20 * time.Millisecond, Heartbeat: time.Hour})
	ctx := ctxFor(t)
	org := td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}
	sa := func(b ...td.Binding) tenancy.Caller {
		return tenancy.Caller{Credential: tenancy.CredAPIKey, Subject: td.Subject{
			Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()}, Bindings: b,
		}}
	}
	investigator := td.Binding{Role: td.RoleInvestigator, Scope: org}
	w.auth.set("investigator", sa(investigator))
	if resp := w.open(t, ctx, stream.Path, "investigator", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Investigator alone: status %d", resp.StatusCode)
	}

	w.auth.set("mixed", sa(investigator, td.Binding{Role: td.RoleViewer, Scope: td.Scope{Type: td.ScopeTeam, ID: w.teamA}}))
	w.event("reflex.alert", agent(w.agentA))    // 1 team A
	w.event("reflex.alert", agent(w.agentB))    // 2 team B: the role alone would show it
	w.event("reflex.incident", agent(w.agentB)) // 3 team B
	w.event("reflex.alert", agent(w.agentA))    // 4 team A
	got, _ := frames(t, w.open(t, ctx, stream.Path, "mixed", map[string]string{"Last-Event-ID": "0"}).Body, untilEvents(2))
	if ev := events(got); len(ev) != 2 || ev[0].id != "1" || ev[1].id != "4" {
		t.Fatalf("mixed: %+v", ev)
	}

	// The recheck drops the role too: once Viewer is gone the stream ends,
	// though Investigator is still bound.
	resp := w.open(t, ctx, stream.Path, "mixed", nil)
	w.auth.set("mixed", sa(investigator))
	if _, closed := frames(t, resp.Body, func([]frame) bool { return false }); !closed {
		t.Fatal("recheck counted the role: stream still open")
	}
}
