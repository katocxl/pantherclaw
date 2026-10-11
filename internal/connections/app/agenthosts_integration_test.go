// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// TestHR183_AgentHostsAreCheckedAndAChangeWeakens: a connection names the
// hosts agents use for its API, which a containment sandbox's edge maps to
// it (G0 M9). They are lowercase host names, distinct, at most 16, and only
// on http and mcp connections; any change weakens enforcement: notified,
// audited with old and new values, and the gateway refetches (HR-183).
func TestHR183_AgentHostsAreCheckedAndAChangeWeakens(t *testing.T) {
	e := newEnv(t)
	c, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "payments", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://payments.example.test/v1/", Gateway: e.gateway,
		AccessMode: app.AccessHeld, CredentialHeader: "Authorization", CredentialScheme: "Bearer", AgentHosts: []string{"api.payments.example"},
	})
	if err != nil || !slices.Equal(c.AgentHosts, []string{"api.payments.example"}) {
		t.Fatalf("create: %v %v", c.AgentHosts, err)
	}
	if e.notes.count("security.connection_weakened") != 0 {
		t.Fatal("creating a connection notified a weakening")
	}

	for name, hosts := range map[string][]string{
		"an upper-case host": {"API.payments.example"},
		"a host with a port": {"api.payments.example:443"},
		"an IP address":      {"192.0.2.10"},
		"a host twice":       {"a.example", "a.example"},
		"an empty host":      {""},
		"17 hosts": {
			"a.x", "b.x", "c.x", "d.x", "e.x", "f.x", "g.x", "h.x", "i.x", "j.x", "k.x", "l.x", "m.x", "n.x", "o.x", "p.x", "q.x",
		},
	} {
		if _, err := e.svc.Create(e.admin, app.CreateInput{
			Name: "bad", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://payments.example.test/v1/", Gateway: e.gateway,
			AccessMode: app.AccessHeld, CredentialHeader: "Authorization", AgentHosts: hosts,
		}); !is(err, app.ErrAgentHosts) {
			t.Errorf("create with %s: %v", name, err)
		}
		if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, AgentHosts: hosts, SetAgentHosts: true}); !is(err, app.ErrAgentHosts) {
			t.Errorf("update to %s: %v", name, err)
		}
	}

	cv := e.configVersion(t, e.gateway)
	u, err := e.svc.Update(e.admin, app.UpdateInput{
		ID: c.ID, Revision: c.Revision, AgentHosts: []string{"api.payments.example", "uploads.payments.example"}, SetAgentHosts: true,
	})
	if err != nil || len(u.AgentHosts) != 2 || u.Revision != c.Revision+1 {
		t.Fatalf("update: %v %v", u.AgentHosts, err)
	}
	if e.notes.count("security.connection_weakened") != 1 || !strings.Contains(e.notes.last["change"], "agent_hosts") ||
		e.configVersion(t, e.gateway) != cv+1 {
		t.Fatalf("an agent hosts change: %v %v", e.notes.types, e.notes.last)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.updated'
		AND convert_from(body, 'UTF8') LIKE '%uploads.payments.example%'`); n != 1 {
		t.Fatalf("%d audit entries name the new agent host", n)
	}
	cleared, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: u.Revision, SetAgentHosts: true})
	if err != nil || len(cleared.AgentHosts) != 0 || e.notes.count("security.connection_weakened") != 2 {
		t.Fatalf("clear: %v %v", cleared.AgentHosts, err)
	}
}
