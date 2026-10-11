// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

type fakeConnectors map[string]*upstream.Client

func (f fakeConnectors) Client(id string) (*upstream.Client, error) {
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
