// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"bufio"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
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
	return sim, upstream.New("http://connector.invalid/mcp", NewStdio(inW, outR, 0)), stop
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

// fakeConnector reads the gateway's lines and answers each request with
// answer(id) when set; with read false it never reads its input.
func fakeConnector(t *testing.T, read bool, answer func(id string) string) (*Stdio, func()) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	stop := func() {
		_ = inR.Close()
		_ = outW.Close()
	}
	t.Cleanup(stop)
	if read {
		go func() {
			sc := bufio.NewScanner(inR)
			for sc.Scan() {
				var m struct {
					ID jsontext.Value `json:"id"`
				}
				if json.Unmarshal(sc.Bytes(), &m) == nil && len(m.ID) > 0 && answer != nil {
					_, _ = io.WriteString(outW, answer(string(m.ID))+"\n")
				}
			}
		}()
	}
	return NewStdio(inW, outR, 1024), stop
}

func post(ctx context.Context, s *Stdio, body string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://connector.invalid/mcp", strings.NewReader(body))
	res, err := s.Open(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	_, err = io.ReadAll(res.Body)
	return err
}

const callLine = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_refund","arguments":{}}}`

// TestHR216_AnAbandonedExchangeLeavesTheConnectorBroken: a call that ends
// before the connector answers (it never does), a write the connector
// never reads, and an answer over the connection's limit each leave the
// connector broken: it may still be working, so it takes no other call
// until it is replaced (G0 M9 design decision 6).
func TestHR216_AnAbandonedExchangeLeavesTheConnectorBroken(t *testing.T) {
	for name, tc := range map[string]struct {
		read   bool
		answer func(string) string
	}{
		"never answers": {true, nil},
		"never reads":   {false, nil},
		"answers too big": {true, func(id string) string {
			return `{"jsonrpc":"2.0","id":` + id + `,"result":"` + strings.Repeat("x", 4096) + `"}`
		}},
	} {
		s, _ := fakeConnector(t, tc.read, tc.answer)
		if !s.Usable() {
			t.Fatalf("%s: unusable before any call", name)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		err := post(ctx, s, callLine)
		cancel()
		if err == nil || s.Usable() {
			t.Fatalf("%s: call = %v, usable %v", name, err, s.Usable())
		}
		if err := post(t.Context(), s, callLine); !errors.Is(err, ErrBroken) {
			t.Fatalf("%s: the next call: %v", name, err)
		}
	}

	// An answered call leaves it usable; Close does not.
	s, _ := fakeConnector(t, true, func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":{}}` })
	if err := post(t.Context(), s, callLine); err != nil || !s.Usable() {
		t.Fatalf("an answered call: %v, usable %v", err, s.Usable())
	}
	s.Close()
	if err := post(t.Context(), s, callLine); !errors.Is(err, ErrBroken) || s.Usable() {
		t.Fatalf("after Close: %v", err)
	}
}
