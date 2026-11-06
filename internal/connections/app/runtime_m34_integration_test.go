// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	m34GatewayARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/orders-gw"
	m34Target     = "agentcore:" + m34GatewayARN + "/orders"
)

// m34MCP is a live mcp connection with the given credential custody.
func (e *env) m34MCP(t *testing.T, name, access string) app.Connection {
	t.Helper()
	c, err := e.svc.Create(e.admin, app.CreateInput{
		Name: name, Kind: app.KindMCP, Package: upstreamPackage, BaseURL: "https://mcp.example.test/" + name, Gateway: e.gateway,
		AccessMode: access,
	})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return c
}

// TestHR762_ARuntimeTargetBindsOneAgentHeldMCPConnection: a person with
// connection.manage binds an agent-held mcp connection to an AgentCore
// target and clears it again, each audited with the gateway refetching its
// configuration; a malformed target, another kind or custody, a target
// another connection holds, a caller without connection.manage, and an
// access-mode change while bound are refused (G0 M34 D991).
//
// Covers: F1040, HR-762
func TestHR762_ARuntimeTargetBindsOneAgentHeldMCPConnection(t *testing.T) {
	e := newEnv(t)
	e.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
	held := e.m34MCP(t, "orders", app.AccessAgentHeld)
	other := e.m34MCP(t, "orders2", app.AccessAgentHeld)
	none := e.m34MCP(t, "nocred", app.AccessNone)
	httpConn := e.payments(t, "payments")

	v0 := e.configVersion(t, e.gateway)
	c, err := e.svc.SetRuntimeTarget(e.admin, held.ID, m34Target)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := deref(c.RuntimeTarget); got != m34Target {
		t.Fatalf("runtime target %q", got)
	}
	if v := e.configVersion(t, e.gateway); v <= v0 {
		t.Errorf("config version %d, was %d: the gateway does not refetch", v, v0)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.runtime_target_set'
		AND convert_from(body, 'UTF8') LIKE '%' || $1 || '%'`, m34GatewayARN); n != 1 {
		t.Errorf("%d runtime_target_set audit entries", n)
	}

	for name, target := range map[string]string{
		"no prefix":              m34GatewayARN + "/orders",
		"another prefix":         "vertex:" + m34GatewayARN + "/orders",
		"no target name":         "agentcore:" + m34GatewayARN,
		"an empty target name":   "agentcore:" + m34GatewayARN + "/",
		"a target name with _":   "agentcore:" + m34GatewayARN + "/a_b",
		"another service":        "agentcore:arn:aws:lambda:us-east-1:123456789012:gateway/x/orders",
		"an 11-digit account":    "agentcore:arn:aws:bedrock-agentcore:us-east-1:12345678901:gateway/x/orders",
		"a runtime, not gateway": "agentcore:arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/x/orders",
		"a wildcard":             "agentcore:arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/*/orders",
		"over 512 characters":    "agentcore:" + m34GatewayARN + "/" + strings.Repeat("a", 520),
	} {
		if _, err := e.svc.SetRuntimeTarget(e.admin, other.ID, target); !is(err, app.ErrRuntimeTarget) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.SetRuntimeTarget(e.admin, other.ID, m34Target); !is(err, app.ErrRuntimeTargetTaken) {
		t.Errorf("a target another connection holds: %v", err)
	}
	if _, err := e.svc.SetRuntimeTarget(e.admin, none.ID, m34Target+"x"); !is(err, app.ErrRuntimeTargetKind) {
		t.Errorf("an mcp connection without an agent-held credential: %v", err)
	}
	if _, err := e.svc.SetRuntimeTarget(e.admin, httpConn.ID, m34Target+"x"); !is(err, app.ErrRuntimeTargetKind) {
		t.Errorf("an http connection: %v", err)
	}
	if _, err := e.svc.SetRuntimeTarget(e.caller(td.KindUser, td.RoleViewer), other.ID, m34Target+"x"); !denied(err) {
		t.Errorf("a viewer: %v", err)
	}
	if _, err := e.svc.ClearRuntimeTarget(e.caller(td.KindUser, td.RoleViewer), held.ID); !denied(err) {
		t.Errorf("a viewer clearing: %v", err)
	}
	if _, err := e.svc.SetRuntimeTarget(e.admin, ids.NewV7(), m34Target+"x"); err == nil {
		t.Error("a connection of no row was bound")
	}
	access := app.AccessNone
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: held.ID, Revision: c.Revision, AccessMode: &access}); !is(err, app.ErrRuntimeTargetKind) {
		t.Errorf("an access-mode change while bound: %v", err)
	}

	// The same target in another org is that org's own.
	o := e.withOrg(t)
	o.pin(t, upstreamPackage, "1.0.0", mcpPayments(t))
	if _, err := o.svc.SetRuntimeTarget(o.admin, o.m34MCP(t, "orders", app.AccessAgentHeld).ID, m34Target); err != nil {
		t.Errorf("another org's connection: %v", err)
	}

	v1 := e.configVersion(t, e.gateway)
	c, err = e.svc.ClearRuntimeTarget(e.admin, held.ID)
	if err != nil || c.RuntimeTarget != nil {
		t.Fatalf("clear: %v %v", deref(c.RuntimeTarget), err)
	}
	if v := e.configVersion(t, e.gateway); v <= v1 {
		t.Errorf("config version %d, was %d after clearing", v, v1)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.runtime_target_cleared'
		AND convert_from(body, 'UTF8') LIKE '%runtime_target_old%'`); n != 1 {
		t.Errorf("%d runtime_target_cleared audit entries naming the old target", n)
	}
	// Cleared, the target is free for another connection.
	if _, err := e.svc.SetRuntimeTarget(e.admin, other.ID, m34Target); err != nil {
		t.Errorf("the freed target: %v", err)
	}
}
