// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"context"
	"encoding/json/jsontext"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// on maps an MCP call through a connection, as the gateway does, and
// evaluates it for the gateway asking.
func (f *fx) on(gateway, conn ids.UUID, tool, input string) *pipeline.Evaluation {
	f.t.Helper()
	p, err := f.mapper.MCP(context.Background(), mapping.Context{
		Org: org.String(), Env: f.env.String(), RunID: f.run.String(), ActionID: ids.NewV7().String(), AgentInstance: f.instance.String(),
		Connection: conn.String(),
	}, tool, jsontext.Value(input))
	if err != nil {
		f.t.Fatal(err)
	}
	return f.eval(pipeline.Request{
		Org: org, Action: p, Identity: pipeline.Identity{InstanceID: f.instance, AgentID: f.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
		Gateway: gateway.String(),
	})
}

func connection(gateway ids.UUID) pipeline.Connection {
	return pipeline.Connection{
		ID: ids.NewV7(), Gateway: gateway, Kind: "http", Package: "pc.mock-payments", State: "ACTIVE", AccessMode: "pantherclaw_held",
		DefaultMode: pipeline.ModeMonitor, Modes: map[string]string{"payments-refund": pipeline.ModeEnforce},
	}
}

// TestHR184_TheConnectionsRouteModeDecidesTheMode: an action through a
// connection takes its route's mode (explicit, or the connection's
// default); without a connection it is enforced.
func TestHR184_TheConnectionsRouteModeDecidesTheMode(t *testing.T) {
	f := newFx(t)
	gw := ids.NewV7()
	c := connection(gw)
	f.w.PutConnection(c)

	ev := f.on(gw, c.ID, "create_refund", refund("ch_1", "10.00"))
	expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
	if ev.Mode != pipeline.ModeEnforce || ev.Connection == nil || ev.Connection.ID != c.ID || ev.MonitorPermit() {
		t.Fatalf("enforced route: mode %s connection %+v", ev.Mode, ev.Connection)
	}
	ev = f.on(gw, c.ID, "get_refund", `{"refund":"re_1"}`)
	if ev.Mode != pipeline.ModeMonitor || !ev.MonitorPermit() {
		t.Fatalf("a route without a mode takes the default: %s", ev.Mode)
	}
}

// TestT067_GatewayActionsNameAConnectionThatServesThem: an action from a
// gateway channel without a connection would escape its route's mode and
// its quarantine, so it cannot be authorized; nor can a definition the
// connection's kind cannot dispatch (PAP-1 §6).
func TestT067_GatewayActionsNameAConnectionThatServesThem(t *testing.T) {
	f := newFx(t)
	p, err := f.mapper.MCP(context.Background(), mapping.Context{
		Org: org.String(), Env: f.env.String(), RunID: f.run.String(), ActionID: ids.NewV7().String(), AgentInstance: f.instance.String(),
	}, "create_refund", jsontext.Value(refund("ch_1", "10.00")))
	if err != nil {
		t.Fatal(err)
	}
	ev := f.eval(pipeline.Request{
		Org: org, Action: p, Identity: pipeline.Identity{InstanceID: f.instance, AgentID: f.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}, Gateway: f.gateway.String(),
	})
	expect(t, ev, adomain.CannotAuthorize, pipeline.ReasonConnectionRequired)
	if ev.Decision.Permits() || ev.MonitorPermit() {
		t.Fatal("an action without its connection got a permit")
	}

	// The mock payments package has HTTP dispatch templates only: an MCP
	// connection to it serves none of its routes.
	gw := ids.NewV7()
	c := connection(gw)
	c.Kind = "mcp"
	f.w.PutConnection(c)
	expect(t, f.on(gw, c.ID, "create_refund", refund("ch_1", "10.00")), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
}

// TestHR184_MonitorModeStillNeedsIdentityAndContainment: a monitor-mode
// action whose policy would deny still gets a monitor permit, but not when
// identity or containment fails, and a quarantined connection is contained.
func TestHR184_MonitorModeStillNeedsIdentityAndContainment(t *testing.T) {
	f := newFx(t)
	gw := ids.NewV7()
	c := connection(gw)
	c.Modes = map[string]string{}
	f.w.PutConnection(c)

	// Over the grant's amount: a hypothetical DENY or CANNOT_AUTHORIZE,
	// which monitor mode never enforces.
	ev := f.on(gw, c.ID, "create_refund", refund("ch_1", "900000.00"))
	if ev.Decision.Permits() || !ev.MonitorPermit() {
		t.Fatalf("monitor over the grant: %s, monitor permit %v", ev.Decision, ev.MonitorPermit())
	}
	f.w.Cont.KillSwitch = true
	if ev := f.on(gw, c.ID, "create_refund", refund("ch_1", "10.00")); ev.MonitorPermit() || ev.Decision != adomain.Deny {
		t.Fatalf("kill switch in monitor mode: %s %v", ev.Decision, ev.MonitorPermit())
	}
	f.w.Cont.KillSwitch = false
	c.State = "QUARANTINED"
	f.w.PutConnection(c)
	ev = f.on(gw, c.ID, "create_refund", refund("ch_1", "10.00"))
	expect(t, ev, adomain.Deny, pipeline.ReasonConnectionContained)
	if ev.MonitorPermit() {
		t.Fatal("a quarantined connection got a monitor permit")
	}
	c.State = "ACTIVE"
	f.w.PutConnection(c)
	other := f.newRun(f.grant.ID)
	f.w.AddRun(other, pipeline.Run{AgentID: ids.NewV7(), InstanceID: ids.NewV7(), Active: true, GrantID: f.grant.ID})
	f.run = other
	if ev := f.on(gw, c.ID, "create_refund", refund("ch_1", "10.00")); ev.MonitorPermit() {
		t.Fatalf("a run of another instance got a monitor permit: %s", ev.Decision)
	}
}

// TestPAP1_AConnectionMustBeTheCallingGatewaysOwn: a connection of
// another gateway, an unknown one, one for another package, and a hook
// call through a non-local connection are refused at step 1.
func TestPAP1_AConnectionMustBeTheCallingGatewaysOwn(t *testing.T) {
	f := newFx(t)
	gw := ids.NewV7()
	c := connection(gw)
	f.w.PutConnection(c)
	expect(t, f.on(ids.NewV7(), c.ID, "create_refund", refund("ch_1", "10.00")), adomain.CannotAuthorize, pipeline.ReasonConnectionUnknown)
	expect(t, f.on(gw, ids.NewV7(), "create_refund", refund("ch_1", "10.00")), adomain.CannotAuthorize, pipeline.ReasonConnectionUnknown)
	wrong := connection(gw)
	wrong.Package = "pc.other"
	f.w.PutConnection(wrong)
	expect(t, f.on(gw, wrong.ID, "create_refund", refund("ch_1", "10.00")), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
	local := connection(gw)
	local.Kind = "local"
	f.w.PutConnection(local)
	expect(t, f.on(gw, local.ID, "create_refund", refund("ch_1", "10.00")), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
	f.w.Fail["Connection"] = true
	expect(t, f.on(gw, c.ID, "create_refund", refund("ch_1", "10.00")), adomain.CannotAuthorize, pipeline.ReasonEvidenceUnavailable)
}

// TestHR201_SDKActionsComeThroughALocalConnection: an action the gateway's
// SDK face mapped (channel sdk) is decided through a local connection,
// whose agent performs it; an MCP call through a local connection is still
// refused, and so is an sdk action through a connection whose kind cannot
// serve its definition.
func TestHR201_SDKActionsComeThroughALocalConnection(t *testing.T) {
	f := newFx(t)
	gw := ids.NewV7()
	sdkOn := func(conn ids.UUID) *pipeline.Evaluation {
		p, err := f.mapper.SDK(context.Background(), mapping.Context{
			Org: org.String(), Env: f.env.String(), RunID: f.run.String(), ActionID: ids.NewV7().String(), AgentInstance: f.instance.String(),
			Connection: conn.String(),
		}, defs.ChannelMCP, "create_refund", jsontext.Value(refund("ch_1", "10.00")))
		if err != nil {
			t.Fatal(err)
		}
		return f.eval(pipeline.Request{
			Org: org, Action: p, Identity: pipeline.Identity{InstanceID: f.instance, AgentID: f.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
			Gateway: gw.String(),
		})
	}
	local := connection(gw)
	local.Kind, local.AccessMode, local.DefaultMode = "local", "none", pipeline.ModeEnforce
	f.w.PutConnection(local)
	ev := sdkOn(local.ID)
	expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
	if ev.Connection == nil || ev.Connection.ID != local.ID {
		t.Fatalf("evaluated connection %+v", ev.Connection)
	}
	expect(t, f.on(gw, local.ID, "create_refund", refund("ch_1", "10.00")), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
	// The mock payments package has no MCP dispatch template.
	mcp := connection(gw)
	mcp.Kind = "mcp"
	f.w.PutConnection(mcp)
	expect(t, sdkOn(mcp.ID), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
}

// TestHR079_PoliciesSeeTheConnectionsDestinationClass: a policy decides on
// action.destination_class, which the Authority takes from the record of
// the connection the action came through.
func TestHR079_PoliciesSeeTheConnectionsDestinationClass(t *testing.T) {
	f := newFx(t)
	rule := pdomain.Rule{
		ID: "internal-only", Kind: pdomain.Forbid, Summary: "refunds only through internal connections",
		Operations: []string{"payments.refund.create"}, When: `action.destination_class != "internal"`, Reason: "PUBLIC_DESTINATION",
	}
	if err := f.w.SetPolicy([]pdomain.Rule{rule}, nil); err != nil {
		t.Fatal(err)
	}
	gw := ids.NewV7()
	public, internal := connection(gw), connection(gw)
	public.DestinationClass, internal.DestinationClass = "public", "internal"
	f.w.PutConnection(public)
	f.w.PutConnection(internal)
	expect(t, f.on(gw, public.ID, "create_refund", refund("ch_1", "10.00")), adomain.Deny, "PUBLIC_DESTINATION")
	ev := f.on(gw, internal.ID, "create_refund", refund("ch_1", "10.00"))
	expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
	if ev.Connection == nil || ev.Connection.DestinationClass != "internal" {
		t.Fatalf("evaluated connection %+v", ev.Connection)
	}
}
