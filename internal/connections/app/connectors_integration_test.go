// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const connectorImage = "registry.example.test/acme/mcp@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestHR084_ConnectorsRunOnlyOnCustomerHostedGateways: a connector
// connection (a stdio MCP server in a container, G0 M9 track C) has no
// base URL and no credential of its own, a spec pinned by digest with
// non-secret environment values, and egress only through an active http
// connection of its gateway. It is refused on, and cannot move to, a
// PantherClaw-hosted gateway, which only the server's configuration names
// (HR-084); replacing its spec weakens enforcement and keeps the history
// (HR-183).
func TestHR084_ConnectorsRunOnlyOnCustomerHostedGateways(t *testing.T) {
	e := newEnv(t)
	e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
	hosted := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'hosted', 'test')", e.org, hosted)
	e.svc.WithPantherClawHosted([]ids.UUID{hosted})
	egress := e.payments(t, "payments")
	spec := func() *app.ConnectorSpec {
		return &app.ConnectorSpec{
			Image: connectorImage, Command: []string{"/server", "--stdio"}, Environment: map[string]string{"LOG_LEVEL": "info-7f3a9c"},
			CredentialPlaceholders: []string{"GITHUB_TOKEN"}, EgressConnection: &egress.ID,
		}
	}
	in := func(gw ids.UUID, s *app.ConnectorSpec) app.CreateInput {
		return app.CreateInput{
			Name: "connector", Kind: app.KindMCPContainer, Package: upstreamPackage, Gateway: gw, AccessMode: app.AccessNone, Connector: s,
		}
	}

	if _, err := e.svc.Create(e.admin, in(hosted, spec())); !is(err, app.ErrHostedGateway) {
		t.Fatalf("a connector on a PantherClaw-hosted gateway: %v", err)
	}
	c, err := e.svc.Create(e.admin, in(e.gateway, spec()))
	if err != nil || c.BaseUrl != nil || c.Connector == nil || c.Connector.Image != connectorImage ||
		!slices.Equal(c.Connector.Command, []string{"/server", "--stdio"}) || c.Connector.MemoryMib != app.DefaultConnectorMemoryMiB ||
		c.Connector.Revision != c.Revision {
		t.Fatalf("create: %+v %v", c.Connector, err)
	}

	other := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", e.org, other)
	mcp, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "upstream", Kind: app.KindMCP, Package: upstreamPackage, BaseURL: "https://mcp.example.test/mcp", Gateway: e.gateway,
		AccessMode: app.AccessNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*app.CreateInput)
		want   error
	}{
		"a tag":              {func(i *app.CreateInput) { i.Connector.Image = "registry.example.test/acme/mcp:latest" }, app.ErrConnector},
		"no command":         {func(i *app.CreateInput) { i.Connector.Command = nil }, app.ErrConnector},
		"a token in the env": {func(i *app.CreateInput) { i.Connector.Environment["TOKEN"] = "ghp_0123456789abcdef" }, app.ErrConnector},
		"a token in the command": {func(i *app.CreateInput) {
			i.Connector.Command = []string{"/server", "--token=" + "ghp_" + strings.Repeat("a", 20)}
		}, app.ErrConnector},
		"a JWT in the env":   {func(i *app.CreateInput) { i.Connector.Environment["SESSION"] = "eyJhbGciOiJIUzI1NiJ9.e30.x" }, app.ErrConnector},
		"an AWS session key": {func(i *app.CreateInput) { i.Connector.Environment["KEY"] = "ASIA0123456789ABCDEF" }, app.ErrConnector},
		"an env over 64 KiB": {func(i *app.CreateInput) {
			for n := range 64 {
				i.Connector.Environment[fmt.Sprintf("V%d", n)] = strings.Repeat("x", 1024)
			}
		}, app.ErrConnector},
		"a lower-case env name":     {func(i *app.CreateInput) { i.Connector.Environment["token"] = "x" }, app.ErrConnector},
		"a placeholder with value":  {func(i *app.CreateInput) { i.Connector.Environment["GITHUB_TOKEN"] = "x" }, app.ErrConnector},
		"egress over mcp":           {func(i *app.CreateInput) { i.Connector.EgressConnection = &mcp.ID }, app.ErrConnector},
		"egress unknown":            {func(i *app.CreateInput) { u := ids.NewV7(); i.Connector.EgressConnection = &u }, app.ErrConnector},
		"egress of another gateway": {func(i *app.CreateInput) { i.Gateway = other }, app.ErrConnector},
		"too much memory":           {func(i *app.CreateInput) { i.Connector.MemoryMiB = 1 << 16 }, app.ErrConnector},
		"no spec":                   {func(i *app.CreateInput) { i.Connector = nil }, app.ErrConnector},
		"a base URL":                {func(i *app.CreateInput) { i.BaseURL = "https://x.example.test" }, app.ErrShape},
		"a held credential":         {func(i *app.CreateInput) { i.AccessMode, i.CredentialHeader = app.AccessHeld, "Authorization" }, app.ErrShape},
		"agent hosts":               {func(i *app.CreateInput) { i.AgentHosts = []string{"api.example.test"} }, app.ErrAgentHosts},
		"a spec on http": {func(i *app.CreateInput) {
			i.Kind, i.BaseURL, i.Package = app.KindHTTP, "https://x.example.test", upstreamPackage
		}, app.ErrConnector},
	} {
		i := in(e.gateway, spec())
		i.Name = "bad"
		tc.mutate(&i)
		if _, err := e.svc.Create(e.admin, i); !is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, Gateway: &hosted, Connector: spec()}); !is(err, app.ErrHostedGateway) {
		t.Fatalf("moving a connector to a PantherClaw-hosted gateway: %v", err)
	}
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, Gateway: &other}); !is(err, app.ErrConnector) {
		t.Fatalf("moving a connector without its spec: %v", err)
	}
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: egress.ID, Revision: egress.Revision, Connector: spec()}); !is(err, app.ErrConnector) {
		t.Fatalf("a spec on an http connection: %v", err)
	}
	weakened := e.notes.count("security.connection_weakened")
	s := spec()
	s.Command = []string{"/server", "--stdio", "--verbose"}
	u, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, Connector: s})
	if err != nil || u.Connector == nil || u.Connector.Revision != u.Revision || !slices.Contains(u.Connector.Command, "--verbose") {
		t.Fatalf("update: %+v %v", u.Connector, err)
	}
	if e.notes.count("security.connection_weakened") != weakened+1 || !strings.Contains(e.notes.last["change"], "connector") {
		t.Fatalf("a spec change: %v %v", e.notes.types, e.notes.last)
	}
	// A change to the environment alone changes what runs (NODE_OPTIONS):
	// it weakens too, and its audit shows the names and the spec's hash.
	s = spec()
	s.Command = []string{"/server", "--stdio", "--verbose"}
	s.Environment["NODE_OPTIONS"] = "--require /srv/hook.js"
	u, err = e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: u.Revision, Connector: s})
	if err != nil || e.notes.count("security.connection_weakened") != weakened+2 || !strings.Contains(e.notes.last["change"], "connector") {
		t.Fatalf("an environment-only change: %v %v %v", err, e.notes.types, e.notes.last)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.connector_specs WHERE connection_id = $1", c.ID); n != 3 {
		t.Fatalf("%d specs kept, want 3", n)
	}
	// Each spec invalidates the connector's coverage (HR-211).
	if n := e.int64(t, `SELECT count(*) FROM pc.coverage_invalidations WHERE connection_id = $1 AND kind = 'connection'
		AND detail = 'connector spec changed'`, c.ID); n != 3 {
		t.Fatalf("%d spec invalidations, want 3", n)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind LIKE 'audit.connection.%'
		AND convert_from(body, 'UTF8') LIKE '%info-7f3a9c%'`); n != 0 {
		t.Fatal("an audit entry carries an environment value")
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind LIKE 'audit.connection.%'
		AND convert_from(body, 'UTF8') LIKE '%NODE_OPTIONS%sha256=%'`); n == 0 {
		t.Fatal("no audit entry shows the environment's names and the spec's hash")
	}
}

// TestHR211_AChangeToAConnectorsEgressConnectionInvalidatesTheConnector: a
// connector reaches the network only through its egress connection, so
// each change that invalidates that connection's coverage (its base URL,
// its hosts, its credential sealed, replaced or revoked, its quarantine)
// also invalidates, in the same transaction, every connector whose current
// spec sends through it; the coverage calculus then drops the connector's
// routes from ENFORCED. A connector that no longer sends through it is
// left alone (G0 M9 design decision 6; HR-211).
func TestHR211_AChangeToAConnectorsEgressConnectionInvalidatesTheConnector(t *testing.T) {
	e := newEnv(t)
	e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
	egress, spare := e.payments(t, "payments"), e.payments(t, "spare")
	connector := func(name string, through ids.UUID) app.Connection {
		c, err := e.svc.Create(e.admin, app.CreateInput{
			Name: name, Kind: app.KindMCPContainer, Package: upstreamPackage, Gateway: e.gateway, AccessMode: app.AccessNone,
			Connector: &app.ConnectorSpec{Image: connectorImage, Command: []string{"/server"}, EgressConnection: &through},
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := connector("connector", egress.ID)
	// moved went through payments, and its current spec sends through spare.
	moved := connector("moved", egress.ID)
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: moved.ID, Revision: moved.Revision, Connector: &app.ConnectorSpec{
		Image: connectorImage, Command: []string{"/server"}, EgressConnection: &spare.ID,
	}}); err != nil {
		t.Fatal(err)
	}
	copies := func(conn ids.UUID) int64 {
		return e.int64(t, `SELECT count(*) FROM pc.coverage_invalidations WHERE connection_id = $1 AND subject_id = $2
			AND kind = 'connection' AND detail LIKE 'egress connection: %'`, conn, egress.ID)
	}

	// A sealed credential needs a broker key of the gateway.
	cert, key := ids.NewV7(), ids.NewV7()
	e.exec(t, `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, 'ENROLL', now(), now() + interval '24 hours')`, e.org, cert, e.gateway, make([]byte, 16), strings.Repeat("A", 43))
	e.exec(t, `INSERT INTO pc.broker_keys (org_id, id, gateway_id, version, public_key, fingerprint, cert_id)
		VALUES ($1, $2, $3, 1, $4, $5, $6)`, e.org, key, e.gateway, make([]byte, 1216), "sha256:"+strings.Repeat("ab", 32), cert)
	blob := append([]byte{0x01}, make([]byte, 1200)...) // the shape of a sealed credential; never opened here
	seal := func(version int) ids.UUID {
		id := ids.NewV7()
		e.exec(t, `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, ARRAY['payments.example.test'], 'Authorization', 'test')`, e.org, id, egress.ID, version, key, blob)
		return id
	}
	var first ids.UUID
	for _, tc := range []struct {
		change string
		do     func()
	}{
		{"its base URL", func() {
			cur := e.int64(t, "SELECT revision FROM pc.connections WHERE id = $1", egress.ID)
			u := "https://payments2.example.test/v1/"
			if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: egress.ID, Revision: int32(cur), BaseURL: &u}); err != nil {
				t.Fatal(err)
			}
		}},
		{"its agent hosts", func() {
			e.exec(t, "UPDATE pc.connections SET agent_hosts = ARRAY['api.payments.example.test'] WHERE id = $1", egress.ID)
		}},
		{"its credential sealed", func() { first = seal(1) }},
		{"its credential replaced", func() {
			e.exec(t, "UPDATE pc.credentials SET state = 'SUPERSEDED', superseded_at = now() WHERE id = $1", first)
			first = seal(2)
		}},
		{"its credential revoked", func() {
			e.exec(t, "UPDATE pc.credentials SET state = 'REVOKED', revoked_at = now(), revoked_by = 'test' WHERE id = $1", first)
		}},
		{"its quarantine", func() {
			if _, err := e.svc.Quarantine(e.admin, egress.ID, "suspected compromise"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		before := copies(c.ID)
		tc.do()
		if copies(c.ID) <= before {
			t.Errorf("%s: the connector was not invalidated", tc.change)
		}
	}
	if n := copies(moved.ID); n != 0 {
		t.Fatalf("a connector that no longer sends through it was invalidated %d times", n)
	}
}
