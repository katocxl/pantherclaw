// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build sandbox

package gateway

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/connectors"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
)

const connectorID = "01920000-0000-7000-8000-0000000000d9"

// TestHR086_AConnectorReachesItsAPIOnlyThroughTheGateway: a connector (the
// MCP simulator over stdio, in its hardened container) whose spec names the
// payments connection for egress runs behind an edge of its own. Its
// create_refund posts the refund to the payments API through that edge;
// the gateway takes the request only during the agent's call to the
// connector, maps it to the call's own operation and target, rebuilds it,
// places the payments credential and sends it with the call's idempotency
// key. The connector never holds the credential and gets the answer
// without it (G0 M9 design decisions 6 and 18; HR-085, HR-086).
func TestHR086_AConnectorReachesItsAPIOnlyThroughTheGateway(t *testing.T) {
	c, e := dockertest.Client(t)
	simImage := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-sim", "internal/gateway/connectors/testdata/sim.Dockerfile")
	edgeImage := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-edge", "deploy/sandbox/edge.Dockerfile")
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().String()
	_ = ln.Close()
	_, port, _ := net.SplitHostPort(listen)

	// The connector's package dispatches refunds to the simulator's tools,
	// pinned to the digests of the definitions it lists.
	tools := mcpsim.New(mcpsim.Faults{}).Tools()
	create, err := upstream.ToolDigest(tools[0])
	if err != nil {
		t.Fatal(err)
	}
	connector, err := compile(t, "", func(raw []byte) []byte {
		for _, r := range [][2]string{
			{
				"    dispatch:\n      http:\n        method: POST\n        path: /v1/refunds\n        body:\n",
				"    dispatch:\n      mcp:\n        tool: create_refund\n        upstream_digest: " + create + "\n        arguments:\n",
			},
			{"        idempotency_header: Idempotency-Key\n", ""},
		} {
			if bytes.Count(raw, []byte(r[0])) != 1 {
				t.Fatalf("mock payments package: %q not found once", r[0])
			}
			raw = bytes.Replace(raw, []byte(r[0]), []byte(r[1]), 1)
		}
		return raw
	})
	if err != nil {
		t.Fatal(err)
	}
	connector.GatewayConnection = &pb.GatewayConnection{
		Id: connectorID, Name: "connector", Kind: "mcp_container", Package: "pc.mock-payments", PackageVersion: "1.0.0",
		DestinationClass: "internal", AccessMode: "none", DefaultMode: "enforce", MaxResponseBytes: 1 << 20, TimeoutMs: 30000,
		State: "ACTIVE", Revision: 1,
		Connector: &pb.ConnectorSpec{
			Image: simImage, Command: []string{"/pantherclaw-sim", "mcp", "--stdio", "--upstream", "https://payments.test"},
			EgressConnectionId: connID, Revision: 1,
		},
	}
	connector.Modes = map[string]string{}

	h := setup(t, withCredential(t, []string{"127.0.0.1"}), func(h *harness) {
		// The connector names the payments API by an agent host: the edge
		// maps names only, never the base URL's IP literal.
		h.conn.AgentHosts = []string{"payments.test"}
		h.extra = []*control.Connection{connector}
		h.connectors = func(conf connectors.Configuration) *connectors.Supervisor {
			sup, err := connectors.New(t.Context(), c, connectors.Config{
				Enabled: true, EdgeImage: edgeImage, EgressListen: listen, EgressAddr: "host.docker.internal:" + port,
			}, conf, pclog.Discard())
			if err != nil {
				t.Fatal(err)
			}
			return sup
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(2 * time.Minute):
			t.Error("the supervisor did not stop")
		}
	})
	go func() {
		defer close(stopped)
		_ = h.sup.Run(ctx)
	}()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if _, err := h.sup.Client(connectorID); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("the connector did not start: %v", err)
		}
		time.Sleep(time.Second)
	}

	r := h.mcpCall(t, http.MethodPost, "/mcp/connector", jsonRPC("tools/call", refundArgs), map[string]string{"Mcp-Name": "create_refund"})
	res := r.body.Result
	if r.code != http.StatusOK || res.IsError || len(res.Content) != 1 || !strings.Contains(res.Content[0].Text, `"re_1"`) {
		t.Fatalf("tools/call = %d %+v %+v", r.code, r.body.Error, res)
	}
	if strings.Contains(res.Content[0].Text, testSecret) {
		t.Fatal("the connector saw the credential")
	}
	if h.target.calls() != 1 {
		t.Fatalf("the target got %d requests, want the call's one", h.target.calls())
	}
	body, hdr := h.target.req(0)
	if body != outbound || hdr.Get("Authorization") != "Bearer "+testSecret || !strings.HasPrefix(hdr.Get("Idempotency-Key"), "pc-") {
		t.Fatalf("target got %s, Authorization %q, Idempotency-Key %q", body, hdr.Get("Authorization"), hdr.Get("Idempotency-Key"))
	}
	if s := h.auth.snap(); len(s.begins) != 1 {
		t.Fatalf("%d dispatches committed, want the agent's one call", len(s.begins))
	}
}
