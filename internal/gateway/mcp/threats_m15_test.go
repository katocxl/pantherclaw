// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestT182_TamperedOrForgedMCPStateIsNotServed: someone who can write the
// server's MCP state (a database operator, or a compromised server) cannot
// make the gateway serve a task, an elicitation or a hold it did not make
// for that binding. A task row whose binding is rewritten, a task or
// elicitation forged with a body the gateway did not seal, and a body
// moved under another task's key are not found; a hold rewritten to
// another binding is not reused (G0 M15 T-182, HR-411, HR-412).
func TestT182_TamperedOrForgedMCPStateIsNotServed(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newFakeState(c.now)
	a, b := replicas(t, f, c)
	bind := binding{conn: holdConn, run: holdRun, instance: holdInst}
	p := heldIR(t, nil)
	k := actionKey(p.Action)
	held := dispatch.Result{Class: dispatch.Held}
	tk := a.newTask(bind, p, k, held, toolResult{}, nil)
	other := heldIR(t, nil)
	tk2 := a.newTask(bind, other, actionKey(other.Action), held, toolResult{}, nil)
	if tk == nil || tk2 == nil {
		t.Fatal("no task")
	}
	exp := timestamppb.New(c.t.Add(time.Hour))
	forge := func(e *pb.MCPStateEntry) {
		f.mu.Lock()
		defer f.mu.Unlock()
		e.Version, e.UpdateTime = 1, timestamppb.New(c.t)
		f.m[fkey(e.GetKind(), e.GetKey())] = e
	}
	// A forged task under a fresh id, with a body the gateway did not seal.
	forgedID := "forged-task-id-forged-task-id-forged-task-i"
	forge(&pb.MCPStateEntry{
		Kind: pb.MCPStateKind_MCP_STATE_KIND_TASK, Key: taskKey(forgedID), ConnectionId: holdConn, RunId: holdRun,
		InstanceId: holdInst, ActionId: ids.NewV7().String(), Status: statusWorking, SealedBody: []byte("not sealed"), ExpireTime: exp,
	})
	if _, claimed, found := b.lookup(forgedID, bind, true); found || claimed {
		t.Fatal("a forged task was found")
	}
	// The second task's body moved under the first task's key.
	f.mu.Lock()
	body2 := f.m[fkey(pb.MCPStateKind_MCP_STATE_KIND_TASK, taskKey(tk2.id))].GetSealedBody()
	f.m[fkey(pb.MCPStateKind_MCP_STATE_KIND_TASK, taskKey(tk.id))].SealedBody = body2
	f.mu.Unlock()
	if _, _, found := b.lookup(tk.id, bind, false); found {
		t.Fatal("a body moved under another task's key was found")
	}
	// A forged elicitation.
	ek := key{0xe3}
	forge(&pb.MCPStateEntry{
		Kind: pb.MCPStateKind_MCP_STATE_KIND_ELICITATION, Key: ek[:], ConnectionId: holdConn, RunId: holdRun, InstanceId: holdInst,
		SealedBody: []byte("not sealed"), ExpireTime: timestamppb.New(c.t.Add(10 * time.Minute)),
	})
	if _, found, err := b.getElicitation(ek); found || err != nil {
		t.Fatalf("a forged elicitation: %v %v", found, err)
	}
	// A hold rewritten to another run is not this call's.
	a.settle(k, bind, p.Action.ActionID, dispatch.Result{Class: dispatch.Held, TransactionID: "txn"})
	f.mu.Lock()
	f.m[fkey(pb.MCPStateKind_MCP_STATE_KIND_HOLD, k[:])].RunId = ids.NewV7().String()
	f.mu.Unlock()
	if _, ok := b.heldAction(k, bind); ok {
		t.Fatal("a hold rewritten to another binding was reused")
	}
}

// TestT183_StateIsNeverReusedAcrossBindingsOrReplicas: what one binding
// leaves on one replica is never served to another connection, run or
// instance on another replica: not its hold, its task (lookup, claim,
// release or cancel), its elicitation or its session (G0 M15 T-183,
// HR-412, HR-413).
func TestT183_StateIsNeverReusedAcrossBindingsOrReplicas(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newFakeState(c.now)
	a, b := replicas(t, f, c)
	bind := binding{conn: holdConn, run: holdRun, instance: holdInst}
	p := heldIR(t, nil)
	k := actionKey(p.Action)
	a.settle(k, bind, p.Action.ActionID, dispatch.Result{Class: dispatch.Held, TransactionID: "txn"})
	tk := a.newTask(bind, p, k, dispatch.Result{Class: dispatch.Held}, toolResult{}, nil)
	ek := key{0xe4}
	if _, err := a.putElicitation(ek, bind, []byte(`{}`), c.t.Add(10*time.Minute), 0); err != nil || tk == nil {
		t.Fatalf("setup: %v %v", err, tk)
	}
	sa := &serverSessions{st: a, seen: map[[sha256.Size]byte]seenSession{}}
	sb := &serverSessions{st: b, seen: map[[sha256.Size]byte]seenSession{}}
	sid, err := sa.open(holdConn, holdInst, "jkt-1", holdRun, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for name, other := range map[string]binding{
		"connection": {conn: ids.NewV7().String(), run: holdRun, instance: holdInst},
		"run":        {conn: holdConn, run: ids.NewV7().String(), instance: holdInst},
		"instance":   {conn: holdConn, run: holdRun, instance: ids.NewV7().String()},
	} {
		if _, ok := b.heldAction(k, other); ok {
			t.Errorf("another %s reused the hold", name)
		}
		if _, claimed, found := b.lookup(tk.id, other, true); found || claimed {
			t.Errorf("another %s found the task", name)
		}
		b.release(tk.id, other)
		if b.cancel(tk.id, other) {
			t.Errorf("another %s canceled the task", name)
		}
		if e, found, _ := b.getElicitation(ek); !found || e.binding == other {
			t.Errorf("the elicitation lost its binding to another %s", name)
		}
		sess, ok, err := sb.get(sid)
		if err != nil || !ok {
			t.Fatalf("the session on the other replica: %v %v", ok, err)
		}
		if sess.binds(other.conn, dispatch.Inbound{Instance: other.instance, JKT: "jkt-1", Run: other.run}) {
			t.Errorf("the session binds another %s", name)
		}
	}
	if sess, _, _ := sb.get(sid); sess.binds(holdConn, dispatch.Inbound{Instance: holdInst, JKT: "jkt-2", Run: holdRun}) {
		t.Error("the session binds another key")
	}
	// A claim by the right binding on the other replica still works: the
	// refusals above changed nothing.
	if _, claimed, found := b.lookup(tk.id, bind, true); !found || !claimed {
		t.Fatal("the task's own binding could not claim it on the other replica")
	}
}
