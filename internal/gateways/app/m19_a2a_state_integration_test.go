// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR411_A2AStateIsPerGatewayAndOrg: an A2A task or context belongs to
// the gateway and org that wrote it; another gateway of the org, or the
// same gateway id in another org, reads nothing; the task's sealed context
// comes back byte for byte; a context carries no body and a task needs one
// (G0 M19 D211).
// Covers: PN-010.7
func TestHR411_A2AStateIsPerGatewayAndOrg(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, a := e.enroll(t, "a")
	_, b := e.enroll(t, "b")
	conn := e.httpConnection(t, a.Gateway)
	svc, clk := e.at(time.Now())
	ctx := context.Background()
	run, inst := ids.NewV7(), ids.NewV7()
	foreign := a
	foreign.Org = ids.New[ids.Org]()
	for _, kind := range []string{app.MCPA2ATask, app.MCPA2AContext} {
		en := app.MCPEntry{Kind: kind, Key: stateKey(kind), Connection: conn, Run: &run, Instance: &inst, ExpireTime: clk.Now().Add(time.Hour)}
		if kind == app.MCPA2ATask {
			en.SealedBody = []byte("sealed context id")
		}
		if v, err := svc.PutMCPState(ctx, a, en, 0); err != nil || v != 1 {
			t.Fatalf("%s: put %d %v", kind, v, err)
		}
		for name, id := range map[string]app.Identity{"another gateway": b, "another org": foreign} {
			if _, err := svc.GetMCPState(ctx, id, kind, en.Key); err == nil {
				t.Errorf("%s: %s read it", kind, name)
			}
			if ok, _ := svc.DeleteMCPState(ctx, id, kind, en.Key, 0); ok {
				t.Errorf("%s: %s deleted it", kind, name)
			}
		}
		got, err := svc.GetMCPState(ctx, a, kind, en.Key)
		if err != nil || !bytes.Equal(got.SealedBody, en.SealedBody) || got.ConnectionID != conn || *got.RunID != run {
			t.Fatalf("%s: get %+v %v", kind, got, err)
		}
		if _, err := svc.GetMCPState(ctx, a, app.MCPTask, en.Key); !errors.Is(err, app.ErrMCPStateNotFound) {
			t.Fatalf("%s read as an MCP task: %v", kind, err)
		}
	}
	bad := []app.MCPEntry{
		{Kind: app.MCPA2ATask, Key: stateKey("no body"), Connection: conn, ExpireTime: clk.Now().Add(time.Hour)},
		{Kind: app.MCPA2AContext, Key: stateKey("body"), Connection: conn, SealedBody: []byte{1}, ExpireTime: clk.Now().Add(time.Hour)},
		{Kind: app.MCPA2ATask, Key: stateKey("action"), Connection: conn, ActionID: "x", SealedBody: []byte{1}, ExpireTime: clk.Now().Add(time.Hour)},
		{Kind: app.MCPA2AContext, Key: stateKey("status"), Connection: conn, Status: "working", ExpireTime: clk.Now().Add(time.Hour)},
		{Kind: app.MCPA2AContext, Key: stateKey("long"), Connection: conn, ExpireTime: clk.Now().Add(2 * time.Hour)},
	}
	for i, en := range bad {
		if _, err := svc.PutMCPState(ctx, a, en, 0); !errors.Is(err, app.ErrMCPStateInvalid) {
			t.Fatalf("bad entry %d: %v", i, err)
		}
	}
}

// TestHR412_EachA2AKindHasTheTaskBounds: each A2A kind is bounded on its
// own like MCP tasks, per caller (its instance, or its run without one),
// and neither uses up the MCP entries
// or the other kind (G0 M19 D211).
// Covers: PN-010.7
func TestHR412_EachA2AKindHasTheTaskBounds(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, a := e.enroll(t, "a")
	conn := e.httpConnection(t, a.Gateway)
	svc, clk := e.at(time.Now())
	ctx := context.Background()
	run, inst := ids.NewV7(), ids.NewV7()
	entry := func(kind, name string, instance *ids.UUID) app.MCPEntry {
		en := app.MCPEntry{Kind: kind, Key: stateKey(kind + name), Connection: conn, Run: &run, Instance: instance, ExpireTime: clk.Now().Add(time.Hour)}
		if kind == app.MCPA2ATask {
			en.SealedBody = []byte{1}
		}
		return en
	}
	for _, kind := range []string{app.MCPA2ATask, app.MCPA2AContext} {
		for i := range app.MaxMCPEntriesPerInstance {
			if _, err := svc.PutMCPState(ctx, a, entry(kind, fmt.Sprint(i), &inst), 0); err != nil {
				t.Fatalf("%s %d: %v", kind, i, err)
			}
		}
		if _, err := svc.PutMCPState(ctx, a, entry(kind, "one-too-many", &inst), 0); !errors.Is(err, app.ErrMCPStateFull) {
			t.Fatalf("%s past the instance bound: %v", kind, err)
		}
		other := ids.NewV7()
		if _, err := svc.PutMCPState(ctx, a, entry(kind, "other instance", &other), 0); err != nil {
			t.Fatalf("%s of another instance: %v", kind, err)
		}
	}
	// A caller without an instance is counted by its run, not with every
	// other caller without one (D218).
	for i := range app.MaxMCPEntriesPerInstance {
		if _, err := svc.PutMCPState(ctx, a, entry(app.MCPA2ATask, fmt.Sprint("no-instance-", i), nil), 0); err != nil {
			t.Fatalf("run without an instance, task %d: %v", i, err)
		}
	}
	if _, err := svc.PutMCPState(ctx, a, entry(app.MCPA2ATask, "no-instance-too-many", nil), 0); !errors.Is(err, app.ErrMCPStateFull) {
		t.Fatalf("past the run's bound: %v", err)
	}
	otherRun := ids.NewV7()
	en := entry(app.MCPA2ATask, "another run", nil)
	en.Run = &otherRun
	if _, err := svc.PutMCPState(ctx, a, en, 0); err != nil {
		t.Fatalf("another run without an instance: %v", err)
	}
	// The MCP entries of the instance are untouched by both kinds.
	hold := app.MCPEntry{
		Kind: app.MCPHold, Key: stateKey("hold"), Connection: conn, Run: &run, Instance: &inst,
		ActionID: ids.NewV7().String(), ExpireTime: clk.Now().Add(time.Hour),
	}
	if _, err := svc.PutMCPState(ctx, a, hold, 0); err != nil {
		t.Fatalf("a hold after the A2A bounds: %v", err)
	}
}
