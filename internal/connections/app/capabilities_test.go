// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
)

// TestF346_ConnectionsDeclareTheirCapabilities: a connection's declaration
// follows from its kind, its access mode, its route modes and its package.
// Only a gateway-dispatched HTTP connection whose credential PantherClaw
// holds, with every route enforced, declares enforcement SUPPORTED; a route
// in monitor mode, a target that only declares it checks action tokens, an
// opaque MCP server, an agent-held or open target and a cooperative local
// connection declare PARTIAL with the limit that makes them so, and then
// discovery, observation and response are PARTIAL too. Operations
// carry their route's mode; permissions are declared only for a credential
// PantherClaw uses, named by the definition's credential scope when it has
// one, each with the operations that need it; what the kind cannot serve
// or verify is a limit.
func TestF346_ConnectionsDeclareTheirCapabilities(t *testing.T) {
	payments, err := manifest.Decode(mockpayments.Package)
	if err != nil {
		t.Fatal(err)
	}
	shell, err := manifest.Decode(pcshell.Package)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(kind, access string) app.Connection {
		return app.Connection{
			PcConnection: dbq.PcConnection{Kind: kind, AccessMode: access, DefaultMode: app.ModeMonitor, TimeoutMs: 2500},
			Routes:       []dbq.PcConnectionRoute{{Route: "payments-refund", Mode: app.ModeEnforce}},
		}
	}
	enforced := func(c app.Connection) app.Connection {
		c.DefaultMode = app.ModeEnforce
		return c
	}
	limits := func(c app.Capabilities) []string {
		var out []string
		for _, l := range c.Limits {
			out = append(out, l.Code)
		}
		return out
	}

	held := app.Declare(enforced(conn(app.KindHTTP, app.AccessHeld)), payments)
	if held.Enforcement.Level != app.Supported || !strings.Contains(held.Enforcement.Detail, "HR-060") ||
		!slices.Contains(held.ResponseActions, "revoke_credential") || len(held.Operations) != 2 || len(held.Limits) != 0 ||
		held.Discovery.Level != app.Supported || held.Observation.Level != app.Supported || held.Response.Level != app.Supported {
		t.Fatalf("held: %+v", held)
	}
	create, get := held.Operations[0], held.Operations[1]
	if create.Operation != "payments.refund.create" || create.Route != "payments-refund" || create.Mode != app.ModeEnforce || !create.Verified ||
		create.Access != "write" || get.Route != "payments-refund-get" || get.Mode != app.ModeEnforce {
		t.Fatalf("operations %+v", held.Operations)
	}
	if len(held.Permissions) != 2 || held.Permissions[0].Name != "read payments.refund" || held.Permissions[1].Name != "write payments.charge" ||
		len(held.Permissions[1].Reasons) != 1 || !strings.HasPrefix(held.Permissions[1].Reasons[0], "payments.refund.create: ") {
		t.Fatalf("permissions %+v", held.Permissions)
	}
	// A definition's credential scope names the permissions it needs.
	scoped, err := manifest.Decode(mockpayments.Package)
	if err != nil {
		t.Fatal(err)
	}
	scoped.Definitions[0].Dispatch.CredentialScope = map[string]string{"refunds": "write", "charges": "read"}
	if c := app.Declare(enforced(conn(app.KindHTTP, app.AccessHeld)), scoped); len(c.Permissions) != 3 ||
		c.Permissions[0].Name != "charges:read" || c.Permissions[2].Name != "refunds:write" || c.Permissions[1].Name != "read payments.refund" ||
		len(c.Permissions[2].Reasons) != 1 || !strings.HasPrefix(c.Permissions[2].Reasons[0], "payments.refund.create: ") {
		t.Fatalf("credential scope: %+v", c.Permissions)
	}
	if !slices.ContainsFunc(held.Failure, func(s string) bool { return strings.Contains(s, "2500 ms") }) {
		t.Fatalf("failure behavior %q", held.Failure)
	}
	// A route in monitor mode is decided and recorded, not enforced.
	if monitored := app.Declare(conn(app.KindHTTP, app.AccessHeld), payments); monitored.Enforcement.Level != app.Partial ||
		!strings.Contains(monitored.Enforcement.Detail, "1 of 2 routes are in monitor mode") || monitored.Operations[1].Mode != app.ModeMonitor ||
		monitored.Response.Level != app.Partial {
		t.Fatalf("a route in monitor mode: %+v", monitored)
	}
	// A target that checks action tokens says so; only a passing
	// target_verifier test would show it (HR-210).
	if tokens := app.Declare(enforced(conn(app.KindHTTP, app.AccessTargetEnforced)), payments); tokens.Enforcement.Level != app.Partial ||
		!slices.Equal(limits(tokens), []string{"VERIFIER_NOT_SHOWN"}) || len(tokens.Permissions) != 2 ||
		slices.Contains(tokens.ResponseActions, "revoke_credential") || tokens.Discovery.Level != app.Partial {
		t.Fatalf("target enforced: %+v", tokens)
	}

	for name, tc := range map[string]struct {
		c      app.Connection
		limits []string
		ops    int
	}{
		"agent held": {conn(app.KindHTTP, app.AccessAgentHeld), []string{"AGENT_HELD_CREDENTIAL"}, 2},
		"open":       {conn(app.KindHTTP, app.AccessNone), []string{"OPEN_TARGET"}, 2},
		// The mock payments package has no MCP dispatch template.
		"mcp":   {conn(app.KindMCP, app.AccessHeld), []string{"OPERATION_NOT_SERVED", "OPERATION_NOT_SERVED"}, 0},
		"local": {conn(app.KindLocal, app.AccessNone), []string{"OPERATION_NOT_SERVED", "OPERATION_NOT_SERVED", "COOPERATIVE"}, 0},
	} {
		c := app.Declare(tc.c, payments)
		if c.Enforcement.Level != app.Partial || !slices.Equal(limits(c), tc.limits) || len(c.Operations) != tc.ops {
			t.Errorf("%s: enforcement %+v, limits %v, operations %d", name, c.Enforcement, limits(c), len(c.Operations))
		}
		if tc.c.AccessMode != app.AccessHeld && len(c.Permissions) != 0 {
			t.Errorf("%s: permissions %+v without a credential of PantherClaw's", name, c.Permissions)
		}
	}

	local := app.Declare(conn(app.KindLocal, app.AccessNone), shell)
	if len(local.Operations) != 1 || local.Operations[0].Route != "shell-command" || local.Operations[0].Mode != app.ModeMonitor ||
		!slices.Equal(limits(local), []string{"EFFECT_UNVERIFIABLE", "COOPERATIVE"}) || len(local.Permissions) != 0 ||
		!slices.ContainsFunc(local.Failure, func(s string) bool { return strings.Contains(s, "HR-200") }) {
		t.Fatalf("local shell: %+v", local)
	}
}
