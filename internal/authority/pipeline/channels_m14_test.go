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
// channel ch.
func (f *fx) onChannel(gateway ids.UUID, conn pipeline.Connection, ch string) *pipeline.Evaluation {
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
		Gateway: gateway.String(),
	})
}

// TestM14_A2AChannelNeedsA2AKind: the a2a channel comes only through an
// a2a connection and an a2a connection serves only it, like hook and local
// (G0 M14 D61).
func TestM14_A2AChannelNeedsA2AKind(t *testing.T) {
	f := newFx(t)
	gw := ids.NewV7()
	c := connection(gw)
	f.w.PutConnection(c)
	expect(t, f.onChannel(gw, c, "a2a"), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
	peer := connection(gw)
	peer.Kind = "a2a"
	f.w.PutConnection(peer)
	expect(t, f.onChannel(gw, peer, "mcp"), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
}
