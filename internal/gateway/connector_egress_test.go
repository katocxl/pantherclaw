// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR085_TheGatewayPlacesTheCredentialOnAConnectorsEgress: a request a
// connector made, mapped through its egress connection, is rebuilt from
// the reviewed definition, carries the credential the gateway places and
// the call's idempotency key, and comes back without the credential.
// Nothing is sent once the containment epoch moved past the call's, under
// the kill switch, or while the egress connection or the connector
// connection is quarantined (G0 M9 design decisions 6 and 18, HR-002).
func TestHR085_TheGatewayPlacesTheCredentialOnAConnectorsEgress(t *testing.T) {
	h := setup(t, withCredential(t, []string{"127.0.0.1"}), func(h *harness) { h.target.echo = "Authorization" })
	ctx := mapping.Context{
		Org: testOrg, Env: testEnv, RunID: "01920000-0000-7000-8000-0000000000f1", ActionID: "01920000-0000-7000-8000-0000000000f2",
		AgentInstance: testAgent, Connection: connID,
	}
	a, err := h.conn.Mapper.HTTP(t.Context(), ctx, http.MethodPost, "/v1/refunds", "",
		[]byte(`{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`))
	if err != nil {
		t.Fatal(err)
	}
	const connectorID = "01920000-0000-7000-8000-0000000000c1"
	connector := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: connectorID, Kind: "mcp_container", State: "ACTIVE"}}
	f := dispatch.Flight{Txn: "txn-1", Action: a, Epoch: 1, Connector: connector}
	res, err := h.gw.engine.ConnectorEgress(t.Context(), h.conn, a, f)
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("egress = %d %v", res.Status, err)
	}
	body, hdr := h.target.req(0)
	if hdr.Get("Authorization") != "Bearer "+testSecret || hdr.Get("Idempotency-Key") != "pc-txn-1" {
		t.Fatalf("target got Authorization %q, Idempotency-Key %q", hdr.Get("Authorization"), hdr.Get("Idempotency-Key"))
	}
	if !strings.Contains(body, `"charge":"ch_1"`) {
		t.Fatalf("target got %s", body)
	}
	if strings.Contains(string(res.Body), testSecret) || !strings.Contains(string(res.Body), "[REDACTED]") {
		t.Fatalf("the credential came back: %q", res.Body)
	}

	for name, contain := range map[string]func(c *fakeContainment) func(){
		"the epoch moved past the call's": func(c *fakeContainment) func() { c.epoch = 2; return func() { c.epoch = 1 } },
		"the kill switch":                 func(c *fakeContainment) func() { c.err = control.ErrKillSwitch; return func() { c.err = nil } },
		"the egress connection quarantined": func(c *fakeContainment) func() {
			c.conns[connID] = "QUARANTINED"
			return func() { delete(c.conns, connID) }
		},
		"the connector quarantined": func(c *fakeContainment) func() {
			c.conns[connectorID] = "QUARANTINED"
			return func() { delete(c.conns, connectorID) }
		},
	} {
		h.containment.mu.Lock()
		undo := contain(h.containment)
		h.containment.mu.Unlock()
		if _, err := h.gw.engine.ConnectorEgress(t.Context(), h.conn, a, f); !errors.Is(err, dispatch.ErrEgressContained) || h.target.calls() != 1 {
			t.Errorf("%s: %v, target %d", name, err, h.target.calls())
		}
		h.containment.mu.Lock()
		undo()
		h.containment.mu.Unlock()
	}
}
