// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
)

const refundArgs = `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`

// stdioSim runs the simulator over stdio and returns it with the gateway's
// MCP client speaking to it through a Stdio, and a function that stops the
// simulator as a container that exits.
func stdioSim(t *testing.T, f mcpsim.Faults) (*mcpsim.Server, *upstream.Client, func()) {
	t.Helper()
	sim := mcpsim.New(f)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		_ = sim.ServeStdio(ctx, inR, outW)
		_ = outW.Close()
	}()
	stop := func() {
		cancel()
		_ = inR.Close()
		_ = outW.Close()
	}
	t.Cleanup(stop)
	return sim, upstream.New("http://connector.invalid/mcp", NewStdio(inW, outR)), stop
}

// TestHR082_AConnectorSpeaksMCPOverStdio: the gateway's MCP client lists
// and calls a connector's tools over its container's standard input and
// output (G0 M9 track C): it learns that the connector speaks 2025-11-25,
// opens a session without a session id, and each call runs once.
func TestHR082_AConnectorSpeaksMCPOverStdio(t *testing.T) {
	sim, c, _ := stdioSim(t, mcpsim.Faults{})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tools, err := c.ListTools(ctx, nil)
	if err != nil || len(tools) == 0 || c.Version() != upstream.Legacy {
		t.Fatalf("tools/list: %d tools, %v (version %q)", len(tools), err, c.Version())
	}
	for range 2 {
		r, err := c.Call(ctx, "create_refund", jsontext.Value(refundArgs), nil, nil)
		if err != nil || r.Status != http.StatusOK || r.IsError || r.Error != nil {
			t.Fatalf("tools/call: %+v %v", r, err)
		}
	}
	if sim.Calls() != 2 {
		t.Fatalf("%d calls ran, want 2", sim.Calls())
	}
}

// TestHR082_AConnectorsRequestsAreRefused: an elicitation, a sampling or
// the roots a connector asks for while a call runs reaches the client,
// which declines or refuses it exactly as over HTTP, and the call
// completes.
func TestHR082_AConnectorsRequestsAreRefused(t *testing.T) {
	ask := []string{"elicitation/create", "sampling/createMessage", "roots/list"}
	sim, c, _ := stdioSim(t, mcpsim.Faults{Ask: ask})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	r, err := c.Call(ctx, "create_refund", jsontext.Value(refundArgs), nil, nil)
	if err != nil || r.IsError || !slices.Equal(r.Declined, ask) {
		t.Fatalf("call = %+v %v", r, err)
	}
	want := []string{"elicitation/create: decline", "sampling/createMessage: error -32601", "roots/list: error -32601"}
	if got := sim.Answers(); !slices.Equal(got, want) {
		t.Fatalf("answers %q, want %q", got, want)
	}
}

// TestAStoppedConnectorIsNotCalled: once the container stopped, a call
// fails at once as not sent.
func TestAStoppedConnectorIsNotCalled(t *testing.T) {
	_, c, stop := stdioSim(t, mcpsim.Faults{})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := c.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	stop()
	_, err := c.Call(ctx, "create_refund", jsontext.Value(refundArgs), nil, nil)
	if err == nil || ctx.Err() != nil {
		t.Fatalf("a call to a stopped connector: %v (%v)", err, ctx.Err())
	}
	if !errors.Is(err, ErrExited) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("a call to a stopped connector: %v", err)
	}
}
