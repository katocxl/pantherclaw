// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

type fakeConnectors map[string]*upstream.Client

func (f fakeConnectors) Client(id string, _ int32) (*upstream.Client, error) {
	if c, ok := f[id]; ok {
		return c, nil
	}
	return nil, errors.New("not running")
}

// TestHR084_AGatewayWithoutConnectorsSendsNothing: on a gateway that runs
// no connectors (connectors.enabled off), a connector connection's call is
// never sent; with them, it goes to the connector's own MCP client, never
// through an egress client.
func TestHR084_AGatewayWithoutConnectorsSendsNothing(t *testing.T) {
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c1", Kind: "mcp_container", Revision: 3}}
	if _, err := (&Engine{}).entry(conn); !errors.Is(err, ErrNoConnectors) {
		t.Fatalf("without connectors: %v", err)
	}
	mc := upstream.New("http://connector.invalid/c1", nil)
	e := &Engine{connectors: fakeConnectors{"c1": mc}, clients: map[string]clientEntry{}}
	ce, err := e.entry(conn)
	if err != nil || ce.mcp != mc || ce.client != nil || ce.revision != 3 {
		t.Fatalf("with connectors: %+v %v", ce, err)
	}
	conn.Id = "c2"
	if _, err := e.entry(conn); err == nil {
		t.Fatal("a connector that is not running was used")
	}
}

// TestAConnectorCallIsBounded: a connector's call runs within the
// connection's timeout (30 s when it names none), so its window closes;
// another connection's call is not bounded here.
func TestAConnectorCallIsBounded(t *testing.T) {
	for ms, want := range map[int32]time.Duration{1500: 1500 * time.Millisecond, 0: defaultConnectorTimeout} {
		ctx, cancel := callWindow(t.Context(), &control.Connection{GatewayConnection: &pb.GatewayConnection{Kind: "mcp_container", TimeoutMs: ms}})
		dl, ok := ctx.Deadline()
		cancel()
		if !ok || time.Until(dl) > want || time.Until(dl) < want-time.Second {
			t.Errorf("timeout %d ms: deadline in %s, want %s", ms, time.Until(dl), want)
		}
	}
	ctx, cancel := callWindow(t.Context(), &control.Connection{GatewayConnection: &pb.GatewayConnection{Kind: "mcp"}})
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Error("an mcp connection's call got a deadline here")
	}
}
