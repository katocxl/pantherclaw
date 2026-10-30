// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	holdOrg  = "01920000-0000-7000-8000-000000000001"
	holdEnv  = "01920000-0000-7000-8000-000000000002"
	holdRun  = "01920000-0000-7000-8000-000000000003"
	holdInst = "01920000-0000-7000-8000-000000000004"
	holdConn = "01920000-0000-7000-8000-000000000005"
)

func heldIR(t *testing.T, edit func(*actionir.ActionIR)) actionir.Parsed {
	t.Helper()
	a := actionir.ActionIR{
		V: actionir.Version, Org: holdOrg, Env: holdEnv, RunID: holdRun, ActionID: ids.NewV7().String(), AgentInstance: holdInst,
		Operation: "payments.refund.create", Channel: "mcp", Route: "payments-refund", Connection: holdConn,
		Definition: actionir.Definition{Package: "pc.mock-payments", Version: "1.0.0", Digest: "sha256:" + strings.Repeat("a", 64)},
		Target:     actionir.Target{Type: "charge", ID: "ch_1"},
		Params:     jsontext.Value(`{"amount":"30.00","currency":"USD"}`),
	}
	if edit != nil {
		edit(&a)
	}
	p, err := actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// TestHR185_OnlyAnIdenticalCallHasTheSameKey: the key ignores the action id
// and the order of members, and changes with any argument, the run, the
// instance or the connection.
func TestHR185_OnlyAnIdenticalCallHasTheSameKey(t *testing.T) {
	base := actionKey(heldIR(t, nil).Action)
	if actionKey(heldIR(t, nil).Action) != base {
		t.Fatal("another action id changed the key")
	}
	reordered := heldIR(t, func(a *actionir.ActionIR) { a.Params = jsontext.Value(`{"currency":"USD","amount":"30.00"}`) })
	if actionKey(reordered.Action) != base {
		t.Fatal("member order changed the key")
	}
	for name, edit := range map[string]func(*actionir.ActionIR){
		"argument":   func(a *actionir.ActionIR) { a.Params = jsontext.Value(`{"amount":"31.00","currency":"USD"}`) },
		"target":     func(a *actionir.ActionIR) { a.Target.ID = "ch_2" },
		"run":        func(a *actionir.ActionIR) { a.RunID = ids.NewV7().String() },
		"instance":   func(a *actionir.ActionIR) { a.AgentInstance = ids.NewV7().String() },
		"connection": func(a *actionir.ActionIR) { a.Connection = ids.NewV7().String() },
	} {
		if actionKey(heldIR(t, edit).Action) == base {
			t.Errorf("another %s has the same key", name)
		}
	}
}

// TestHR185_HoldsEndWithTheirDecision: a hold is remembered; an answer
// that decided nothing keeps it; a decision or the hold's lifetime ends it.
func TestHR185_HoldsEndWithTheirDecision(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s := newStore(c.now)
	b := binding{conn: holdConn, run: holdRun, instance: holdInst}
	k := actionKey(heldIR(t, nil).Action)
	s.settle(k, b, "act-1", dispatch.Result{Class: dispatch.Held, TransactionID: "txn-1"})
	if a, ok := s.heldAction(k, b); !ok || a != "act-1" {
		t.Fatalf("held = %q %v", a, ok)
	}
	s.settle(k, b, "act-1", dispatch.Result{Class: dispatch.CannotAuthorize, Code: dispatch.CodeAuthorityUnavailable})
	if _, ok := s.heldAction(k, b); !ok {
		t.Fatal("an answer without a decision ended the hold")
	}
	s.settle(k, b, "act-1", dispatch.Result{Class: dispatch.PolicyDenied, TransactionID: "txn-1"})
	if _, ok := s.heldAction(k, b); ok {
		t.Fatal("a denial kept the hold")
	}
	s.settle(k, b, "act-2", dispatch.Result{Class: dispatch.Held, TransactionID: "txn-2"})
	c.t = c.t.Add(holdTTL)
	if _, ok := s.heldAction(k, b); ok {
		t.Fatal("an expired hold was reused")
	}
}

// TestHR185_TasksBelongToTheirBinding: a task is found only by the
// connection, run and instance that created it, until it expires; one poll
// at a time resubmits it; a cancel from another binding does nothing.
func TestHR185_TasksBelongToTheirBinding(t *testing.T) {
	for name, store := range map[string]func(c *clock) holdStore{
		"memory": func(c *clock) holdStore { return newStore(c.now) },
		// G0 M15 D16: the server store keeps the same contract.
		"server": func(c *clock) holdStore {
			return newServerState(newFakeState(c.now), newTestSealer(t), holdOrg, "gw-1", c.now)
		},
	} {
		t.Run(name, func(t *testing.T) { tasksBelongToTheirBinding(t, store) })
	}
}

func tasksBelongToTheirBinding(t *testing.T, store func(*clock) holdStore) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s := store(c)
	b := binding{conn: holdConn, run: holdRun, instance: holdInst}
	p := heldIR(t, nil)
	k := actionKey(p.Action)
	tk := s.newTask(b, p, k, dispatch.Result{Class: dispatch.Held}, toolResult{}, nil)
	if tk == nil || len(tk.id) != 43 || tk.status != statusWorking {
		t.Fatalf("task %+v", tk)
	}
	if again := s.newTask(b, p, k, dispatch.Result{Class: dispatch.Held}, toolResult{}, nil); again == nil || again.id != tk.id {
		t.Fatal("an identical held call made a second task")
	}
	for name, other := range map[string]binding{
		"connection": {conn: ids.NewV7().String(), run: holdRun, instance: holdInst},
		"run":        {conn: holdConn, run: ids.NewV7().String(), instance: holdInst},
		"instance":   {conn: holdConn, run: holdRun, instance: ids.NewV7().String()},
	} {
		if _, claimed, found := s.lookup(tk.id, other, true); found || claimed {
			t.Errorf("another %s found the task", name)
		}
		if s.cancel(tk.id, other) {
			t.Errorf("another %s canceled the task", name)
		}
	}
	if _, claimed, found := s.lookup(tk.id, b, true); !found || !claimed {
		t.Fatal("the creating binding could not resubmit")
	}
	if _, claimed, found := s.lookup(tk.id, b, true); !found || claimed {
		t.Fatal("two polls resubmitted at once")
	}
	s.release(tk.id, b)
	snap, claimed, _ := s.lookup(tk.id, b, true)
	if !claimed {
		t.Fatal("a released task could not be resubmitted")
	}
	if done := s.finish(snap, dispatch.Result{Class: dispatch.Held}, toolResult{}); done.status != statusWorking || done.busy {
		t.Fatalf("still held: %+v", done)
	}
	snap, _, _ = s.lookup(tk.id, b, true)
	if done := s.finish(snap, dispatch.Result{}, toolResult{ResultType: "complete"}); done.status != statusCompleted || done.result == nil {
		t.Fatalf("allowed: %+v", done)
	}
	if _, claimed, found := s.lookup(tk.id, b, true); !found || claimed {
		t.Fatal("a completed task was resubmitted")
	}
	c.t = c.t.Add(holdTTL)
	if _, _, found := s.lookup(tk.id, b, false); found {
		t.Fatal("an expired task was found")
	}
	tk = s.newTask(b, p, k, dispatch.Result{Class: dispatch.Held}, toolResult{}, nil)
	if !s.cancel(tk.id, b) {
		t.Fatal("the creating binding could not cancel")
	}
	if _, _, found := s.lookup(tk.id, b, false); found {
		t.Fatal("a canceled task was found")
	}
	if m, ok := s.(*memoryStore); ok && (len(m.tasks) != 0 || m.bytes != 0) {
		t.Fatalf("store not empty: %d tasks, %d bytes", len(m.tasks), m.bytes)
	}
}

// TestHR185_HoldsAndTasksAreBounded: an instance keeps at most
// maxPerInstance entries; beyond them nothing is remembered for it, and
// other instances are unaffected.
func TestHR185_HoldsAndTasksAreBounded(t *testing.T) {
	s := newStore(time.Now)
	b := binding{conn: holdConn, run: holdRun, instance: holdInst}
	held := dispatch.Result{Class: dispatch.Held, TransactionID: "txn"}
	for i := range maxPerInstance {
		s.settle(key{byte(i), 1}, b, "act", held)
	}
	s.settle(key{0xff}, b, "act", held)
	if _, ok := s.heldAction(key{0xff}, b); ok {
		t.Fatal("an instance went past its bound")
	}
	if s.newTask(b, heldIR(t, nil), key{0xfe}, held, toolResult{}, nil) != nil {
		t.Fatal("a task went past the bound")
	}
	other := binding{conn: holdConn, run: holdRun, instance: ids.NewV7().String()}
	s.settle(key{0xfd}, other, "act", held)
	if _, ok := s.heldAction(key{0xfd}, other); !ok {
		t.Fatal("another instance was refused")
	}
}

// TestHR185_OnlyDeclaringClientsGetTasks: the tasks extension must be in
// the request's client capabilities.
func TestHR185_OnlyDeclaringClientsGetTasks(t *testing.T) {
	for meta, want := range map[string]bool{
		`{"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`: true,
		`{"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.example/other":{}}}}`:              false,
		`{"io.modelcontextprotocol/clientCapabilities":{}}`:                                                  false,
		`{"io.modelcontextprotocol/clientCapabilities":[]}`:                                                  false,
		`{}`: false,
	} {
		var m map[string]jsontext.Value
		if err := json.Unmarshal([]byte(meta), &m); err != nil {
			t.Fatal(err)
		}
		if supportsTasks(m) != want {
			t.Errorf("%s: %v", meta, !want)
		}
	}
}
