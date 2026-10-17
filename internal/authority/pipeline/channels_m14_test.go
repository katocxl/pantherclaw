// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"context"
	"encoding/json/jsontext"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// onChannel maps a refund through conn as the gateway does and puts it on
// channel ch, as a gateway (external false) or the external decision path
// would submit it.
func (f *fx) onChannel(gateway ids.UUID, conn pipeline.Connection, ch string, external bool) *pipeline.Evaluation {
	f.t.Helper()
	p, err := f.mapper.MCP(context.Background(), mapping.Context{
		Org: org.String(), Env: f.env.String(), RunID: f.run.String(), ActionID: ids.NewV7().String(), AgentInstance: f.instance.String(),
		Connection: conn.ID.String(),
	}, "create_refund", jsontext.Value(refund("ch_1", "10.00")))
	if err != nil {
		f.t.Fatal(err)
	}
	p.Action.Channel = ch
	return f.eval(pipeline.Request{
		Org: org, Action: p, Identity: pipeline.Identity{InstanceID: f.instance, AgentID: f.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
		Gateway: gateway.String(), External: external,
	})
}

// TestM14_GatewayCannotSubmitAuthZENChannel: an action on the authzen
// channel is decided only on the external decision path; from a gateway
// it is CANNOT_AUTHORIZE CHANNEL_NOT_ALLOWED with no permit, and the
// external path decides no other channel (G0 M14 D61).
func TestM14_GatewayCannotSubmitAuthZENChannel(t *testing.T) {
	f := newFx(t)
	gw := ids.NewV7()
	c := connection(gw)
	c.AccessMode = "agent_held"
	f.w.PutConnection(c)

	ev := f.onChannel(gw, c, "authzen", false)
	expect(t, ev, adomain.CannotAuthorize, pipeline.ReasonChannelNotAllowed)
	if ev.Decision.Permits() || ev.MonitorPermit() {
		t.Fatal("a gateway's authzen action got a permit")
	}
	ev = f.onChannel(gw, c, "mcp", true)
	expect(t, ev, adomain.CannotAuthorize, pipeline.ReasonChannelNotAllowed)
	ev = f.onChannel(gw, c, "authzen", true)
	if ev.Decision != adomain.Allow {
		t.Fatalf("the external path's authzen action: %s %+v", ev.Decision, ev.Decisive())
	}
}

// TestM14_A2AChannelNeedsA2AKind: the a2a channel comes only through an
// a2a connection and an a2a connection serves only it, like hook and local
// (G0 M14 D61).
func TestM14_A2AChannelNeedsA2AKind(t *testing.T) {
	f := newFx(t)
	gw := ids.NewV7()
	c := connection(gw)
	f.w.PutConnection(c)
	expect(t, f.onChannel(gw, c, "a2a", false), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
	peer := connection(gw)
	peer.Kind = "a2a"
	f.w.PutConnection(peer)
	expect(t, f.onChannel(gw, peer, "mcp", false), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
}
