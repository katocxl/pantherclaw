// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/simcheck"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// TestM14_ASimulatedPeerIsHandshaken: a simulated a2a connection with a
// registered sender is dispatched only after its simulator answers the
// handshake at its interface URL; a simulated postgres connection, which
// has no HTTP handshake, stays unverified (G0 M14 D100, HR-221).
func TestM14_ASimulatedPeerIsHandshaken(t *testing.T) {
	prev, had := kindSenders["a2a"]
	kindSenders["a2a"] = func(*Engine, context.Context, Result, *control.Connection, *defs.Definition, actionir.Parsed, permitWant, *timer) Result {
		return Result{}
	}
	defer func() {
		if had {
			kindSenders["a2a"] = prev
		} else {
			delete(kindSenders, "a2a")
		}
	}()
	ts := httptest.NewServer(handshake.Wrap("a2a", http.NotFoundHandler()))
	t.Cleanup(ts.Close)
	e := &Engine{
		clients: map[string]clientEntry{}, sims: simcheck.New(), log: slog.New(slog.DiscardHandler),
		allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}
	conn := func(kind, base string) *control.Connection {
		return &control.Connection{GatewayConnection: &pb.GatewayConnection{
			Id: "01920000-0000-7000-8000-0000000000c1", Kind: kind, BaseUrl: base, Simulated: true, Revision: 1, TimeoutMs: 2000,
		}}
	}
	if code := e.simulatorRefusal(context.Background(), conn("a2a", ts.URL)); code != "" {
		t.Fatalf("an a2a simulator: %s", code)
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dead.Close)
	if code := e.simulatorRefusal(context.Background(), conn("a2a", dead.URL)); code != CodeSimulatorUnverified {
		t.Fatalf("no handshake: %q", code)
	}
	if code := e.simulatorRefusal(context.Background(), conn("postgres", "")); code != CodeSimulatorUnverified {
		t.Fatalf("a simulated postgres connection: %q", code)
	}
}
