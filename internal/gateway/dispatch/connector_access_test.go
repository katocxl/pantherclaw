// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// flown keeps the flight a connector was given.
type flown struct{ f Flight }

func (c *flown) Client(string, int32) (*upstream.Client, error) { return nil, nil }

func (c *flown) Fly(_ context.Context, _ string, f Flight) (func(), error) {
	c.f = f
	return func() {}, nil
}

// TestTheConnectorCallsReceiptGetsItsEgressCredentialAccess: the credential
// access a connector's egress set on its flight (what was minted, granted
// and revoked, ADR-0021) is what the call's receipt records; a call whose
// egress placed none records none, and another connection's call has no
// flight.
func TestTheConnectorCallsReceiptGetsItsEgressCredentialAccess(t *testing.T) {
	c := &flown{}
	e := &Engine{connectors: c}
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "k", Kind: "mcp_container"}}
	_, access, err := e.fly(t.Context(), conn, actionir.Parsed{}, permitWant{Txn: "t"})
	if err != nil || access() != nil {
		t.Fatalf("before any egress: %v %v", access(), err)
	}
	granted := &pb.CredentialAccess{InstallationId: 7, Repository: "acme/payments", Granted: map[string]string{"pull_requests": "write"}}
	c.f.access.set(granted)
	if got := access(); got != granted {
		t.Fatalf("the receipt's access: %v", got)
	}
	c.f.access.set(nil) // a request that placed nothing keeps the last access
	if got := access(); got != granted {
		t.Fatalf("after a request without a credential: %v", got)
	}

	c.f = Flight{}
	_, access, err = e.fly(t.Context(), &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "h", Kind: "http"}}, actionir.Parsed{}, permitWant{})
	if err != nil || access() != nil || c.f.Txn != "" {
		t.Fatalf("another connection's call flew: %+v %v", c.f, err)
	}
}
