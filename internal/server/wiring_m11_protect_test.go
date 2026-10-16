// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/protect"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM11ProtectWiring (G0 M11 D96, D110 P1): on the process's one core,
// in the API and in a worker-only process alike, the protect Gate's change
// requests are the core's change ceremony, protect's change kinds are
// registered on it (so the expiry sweep reaches their Closed), and the
// change service and the automations service refuse compromised people
// through the same publishers. Promotions stay NOT_YET until the top wires
// govern.
func TestM11ProtectWiring(t *testing.T) {
	for _, role := range []string{RoleAPI, RoleWorker} {
		t.Run(role, func(t *testing.T) {
			pool := &db.Pool{}
			core, p := newM11Core(pool, nil, "https://pc.example.test")
			if role == RoleWorker {
				attachM11Issuance(core, pool) // as cmdServe does before the role split (D113)
				if _, err := registerAutomationsCoreJobs(nil, jobs.NewRegistry(), core, nil); err != nil {
					t.Fatal(err)
				}
			}
			c, ok := p.gate.Requests.(protect.Ceremony)
			if !ok || c.Changes == nil || c.Changes != core.changes {
				t.Fatalf("the Gate's Requests is %#v, not the core's change ceremony", p.gate.Requests)
			}
			if core.changes.Compromise == nil || core.changes.Compromise != p.publishers {
				t.Fatal("the change service does not refuse compromised people")
			}
			if core.svc.Compromise == nil || core.svc.Compromise != p.publishers {
				t.Fatal("the automations service does not refuse compromised people")
			}
			if p.gate.Failures == nil {
				t.Fatal("an expired emergency review records no failure")
			}
			if p.publishers.Undo[protect.ItemPromotion] == nil {
				t.Fatal("promotion ROLLBACK has no answer")
			}
			org := ids.New[ids.Org]()
			admin := tapp.Caller{
				Subject: td.Subject{
					Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
					Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
				},
				Credential: tapp.CredBrowserSession,
			}
			for _, k := range []struct{ domain, kind string }{
				{protect.DomainProtected, string(protect.ConsequenceRules)},
				{protect.DomainProtected, protect.KindSettings},
				{protect.DomainProtected, protect.KindEmergencyReview},
				{protect.DomainPublisher, protect.KindClear},
			} {
				r := changes.Request{Domain: k.domain, Kind: k.kind, State: changes.StatePending, RequestedBy: "user:other"}
				if !core.changes.MayDecline(admin, r) {
					t.Errorf("%s/%s is not registered on the core's change ceremony", k.domain, k.kind)
				}
			}
		})
	}
}
