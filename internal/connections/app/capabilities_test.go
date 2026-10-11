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
// follows from its kind, its access mode and its package. Only a gateway-
// dispatched HTTP connection whose credential PantherClaw holds, or whose
// target checks action tokens, declares enforcement SUPPORTED; an opaque
// MCP server, an agent-held or open target and a cooperative local
// connection declare PARTIAL with the limit that makes them so. Operations
// carry their route's mode; permissions are declared only for a credential
// PantherClaw uses, each with the operations that need it; what the kind
// cannot serve or verify is a limit.
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
	limits := func(c app.Capabilities) []string {
		var out []string
		for _, l := range c.Limits {
			out = append(out, l.Code)
		}
		return out
	}

	held := app.Declare(conn(app.KindHTTP, app.AccessHeld), payments)
	if held.Enforcement.Level != app.Supported || !strings.Contains(held.Enforcement.Detail, "HR-060") ||
		!slices.Contains(held.ResponseActions, "revoke_credential") || len(held.Operations) != 2 || len(held.Limits) != 0 {
		t.Fatalf("held: %+v", held)
	}
	create, get := held.Operations[0], held.Operations[1]
	if create.Operation != "payments.refund.create" || create.Route != "payments-refund" || create.Mode != app.ModeEnforce || !create.Verified ||
		create.Access != "write" || get.Route != "payments-refund-get" || get.Mode != app.ModeMonitor {
		t.Fatalf("operations %+v", held.Operations)
	}
	if len(held.Permissions) != 2 || held.Permissions[0].Name != "read payments.refund" || held.Permissions[1].Name != "write payments.charge" ||
		len(held.Permissions[1].Reasons) != 1 || !strings.HasPrefix(held.Permissions[1].Reasons[0], "payments.refund.create: ") {
		t.Fatalf("permissions %+v", held.Permissions)
	}
	if !slices.ContainsFunc(held.Failure, func(s string) bool { return strings.Contains(s, "2500 ms") }) {
		t.Fatalf("failure behavior %q", held.Failure)
	}
	if tokens := app.Declare(conn(app.KindHTTP, app.AccessTargetEnforced), payments); tokens.Enforcement.Level != app.Supported ||
		len(tokens.Permissions) != 2 || slices.Contains(tokens.ResponseActions, "revoke_credential") {
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
		"local": {conn(app.KindLocal, app.AccessNone), []string{"COOPERATIVE"}, 2},
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
