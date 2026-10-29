// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// fakeState is GatewayService's MCP state for one gateway as the server
// keeps it (D12): compare-and-set versions, expiry, and every request it
// saw.
type fakeState struct {
	now  func() time.Time
	mu   sync.Mutex
	m    map[string]*pb.MCPStateEntry
	down bool
	seen [][]byte // every key and body sent
}

func newFakeState(now func() time.Time) *fakeState {
	return &fakeState{now: now, m: map[string]*pb.MCPStateEntry{}}
}

func fkey(kind pb.MCPStateKind, k []byte) string { return kind.String() + string(k) }

var errDown = connect.NewError(connect.CodeUnavailable, "down")

func (f *fakeState) live(id string) (*pb.MCPStateEntry, bool) {
	e, ok := f.m[id]
	if ok && !f.now().Before(e.GetExpireTime().AsTime()) {
		return nil, false
	}
	return e, ok
}

func (f *fakeState) PutMCPState(_ context.Context, r *pb.PutMCPStateRequest) (*pb.PutMCPStateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errDown
	}
	e := proto.Clone(r.GetEntry()).(*pb.MCPStateEntry)
	f.seen = append(f.seen, e.GetKey(), e.GetSealedBody())
	id := fkey(e.GetKind(), e.GetKey())
	cur, ok := f.live(id)
	if (r.GetIfVersion() == 0 && ok) || (r.GetIfVersion() != 0 && (!ok || cur.GetVersion() != r.GetIfVersion())) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "MCP_STATE_CONFLICT")
	}
	e.Version, e.UpdateTime = r.GetIfVersion()+1, timestamppb.New(f.now())
	f.m[id] = e
	return &pb.PutMCPStateResponse{Version: e.Version}, nil
}

func (f *fakeState) GetMCPState(_ context.Context, r *pb.GetMCPStateRequest) (*pb.GetMCPStateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errDown
	}
	e, ok := f.live(fkey(r.GetKind(), r.GetKey()))
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, "MCP_STATE_NOT_FOUND")
	}
	return &pb.GetMCPStateResponse{Entry: proto.Clone(e).(*pb.MCPStateEntry)}, nil
}

func (f *fakeState) DeleteMCPState(_ context.Context, r *pb.DeleteMCPStateRequest) (*pb.DeleteMCPStateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errDown
	}
	id := fkey(r.GetKind(), r.GetKey())
	cur, ok := f.live(id)
	if !ok {
		return &pb.DeleteMCPStateResponse{}, nil
	}
	if r.GetIfVersion() != 0 && cur.GetVersion() != r.GetIfVersion() {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "MCP_STATE_CONFLICT")
	}
	delete(f.m, id)
	return &pb.DeleteMCPStateResponse{Deleted: true}, nil
}

// testSealer seals as broker.Key does, with a key of its own.
type testSealer struct{ k *pccrypto.SealPrivateKey }

func newTestSealer(t *testing.T) testSealer {
	t.Helper()
	k, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	return testSealer{k: k}
}

func (s testSealer) SealState(aad, pt []byte) ([]byte, error) {
	return pccrypto.Seal(s.k.PublicKey(), []byte("pc.mcp_state.v1"), aad, pt)
}

func (s testSealer) OpenState(aad, sealed []byte) ([]byte, error) {
	return pccrypto.Open(s.k, []byte("pc.mcp_state.v1"), aad, sealed)
}

func (s testSealer) TaskIDKey(gateway string) ([]byte, error) {
	raw, err := s.k.Bytes()
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, raw, []byte(gateway), "pc.mcp_task_id.v1", sha256.Size)
}

// replicas returns two server stores of one gateway sharing f and the
// broker key, as two gateway processes are.
func replicas(t *testing.T, f *fakeState, c *clock) (*serverState, *serverState) {
	t.Helper()
	sealer := newTestSealer(t)
	return newServerState(f, sealer, holdOrg, "gw-1", c.now), newServerState(f, sealer, holdOrg, "gw-1", c.now)
}

// TestHR411_HoldsAndTasksAreSharedByEveryReplica: a hold remembered by one
// replica is reused by another; a task created on one is polled, claimed
// once, finished and canceled on another, only by its binding; its body
// is sealed and the server never sees the action (G0 M15 D12..D14).
func TestHR411_HoldsAndTasksAreSharedByEveryReplica(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newFakeState(c.now)
	a, b := replicas(t, f, c)
	bind := binding{conn: holdConn, run: holdRun, instance: holdInst}
	p := heldIR(t, nil)
	k := actionKey(p.Action)

	a.settle(k, bind, p.Action.ActionID, dispatch.Result{Class: dispatch.Held, TransactionID: "txn-1"})
	if got, ok := b.heldAction(k); !ok || got != p.Action.ActionID {
		t.Fatalf("held on the other replica = %q %v", got, ok)
	}
	a.settle(k, bind, p.Action.ActionID, dispatch.Result{Class: dispatch.Held, TransactionID: "txn-1"})
	if _, ok := b.heldAction(k); !ok {
		t.Fatal("holding the same call again lost the hold")
	}

	tk := a.newTask(bind, p, k, dispatch.Result{Class: dispatch.Held}, toolResult{})
	if tk == nil || len(tk.id) != 43 || tk.status != statusWorking {
		t.Fatalf("task %+v", tk)
	}
	for _, sent := range f.seen {
		if bytes.Contains(sent, []byte(p.Action.ActionID)) || bytes.Contains(sent, []byte("ch_1")) || bytes.Contains(sent, []byte(tk.id)) {
			t.Fatal("the server saw the action or the task id")
		}
	}
	for name, other := range map[string]binding{
		"connection": {conn: ids.NewV7().String(), run: holdRun, instance: holdInst},
		"run":        {conn: holdConn, run: ids.NewV7().String(), instance: holdInst},
		"instance":   {conn: holdConn, run: holdRun, instance: ids.NewV7().String()},
	} {
		if _, claimed, found := b.lookup(tk.id, other, true); found || claimed {
			t.Errorf("another %s found the task", name)
		}
		if b.cancel(tk.id, other) {
			t.Errorf("another %s canceled the task", name)
		}
	}
	snap, claimed, found := b.lookup(tk.id, bind, true)
	if !found || !claimed || snap.action.Action.ActionID != p.Action.ActionID || !bytes.Equal(snap.action.Canonical, p.Canonical) {
		t.Fatalf("the other replica could not resubmit: %v %v %+v", found, claimed, snap.action.Action)
	}
	if _, claimed, found := a.lookup(tk.id, bind, true); !found || claimed {
		t.Fatal("two replicas resubmitted at once")
	}
	if done := b.finish(snap, dispatch.Result{Class: dispatch.Held}, toolResult{}); done.status != statusWorking || done.busy {
		t.Fatalf("still held: %+v", done)
	}
	_, claimed, _ = a.lookup(tk.id, bind, true)
	if !claimed {
		t.Fatal("a finished claim was not released")
	}
	a.release(tk.id)
	snap, claimed, _ = b.lookup(tk.id, bind, true)
	if !claimed {
		t.Fatal("a released task could not be resubmitted")
	}
	done := b.finish(snap, dispatch.Result{}, toolResult{ResultType: "complete", Content: []content{{Type: "text", Text: "done"}}})
	if done.status != statusCompleted || done.result == nil {
		t.Fatalf("allowed: %+v", done)
	}
	if got, _, found := a.lookup(tk.id, bind, false); !found || got.status != statusCompleted || got.result == nil || got.result.ResultType != "complete" {
		t.Fatalf("the completed task on the first replica: %+v", got)
	}
	c.t = c.t.Add(holdTTL)
	if _, _, found := a.lookup(tk.id, bind, false); found {
		t.Fatal("an expired task was found")
	}
	tk = b.newTask(bind, p, k, dispatch.Result{Class: dispatch.Held}, toolResult{})
	b.settle(k, bind, p.Action.ActionID, dispatch.Result{Class: dispatch.Held})
	if !a.cancel(tk.id, bind) {
		t.Fatal("the creating binding could not cancel on the other replica")
	}
	if _, _, found := b.lookup(tk.id, bind, false); found {
		t.Fatal("a canceled task was found")
	}
	if _, ok := b.heldAction(k); ok {
		t.Fatal("canceling a task kept the hold of its call")
	}
}

// TestHR412_AStateMissOnlyCostsANewAction: with the server out of reach a
// hold is not remembered and no task is made; a body that does not open
// (another broker key) is not found; without a broker key no task is kept.
func TestHR412_AStateMissOnlyCostsANewAction(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newFakeState(c.now)
	a, _ := replicas(t, f, c)
	bind := binding{conn: holdConn, run: holdRun, instance: holdInst}
	p := heldIR(t, nil)
	k := actionKey(p.Action)
	tk := a.newTask(bind, p, k, dispatch.Result{Class: dispatch.Held}, toolResult{})
	if tk == nil {
		t.Fatal("no task")
	}
	rotated := newServerState(f, newTestSealer(t), holdOrg, "gw-1", c.now)
	if _, _, found := rotated.lookup(tk.id, bind, true); found {
		t.Fatal("a body sealed to another key was found")
	}
	// Without a broker key a task stays in its process, as before M15.
	sent := len(f.seen)
	local := newServerState(f, nil, holdOrg, "gw-1", c.now)
	lt := local.newTask(bind, p, k, dispatch.Result{Class: dispatch.Held}, toolResult{})
	if lt == nil || len(f.seen) != sent {
		t.Fatal("a task without a broker key was not kept locally, or was sent")
	}
	if _, _, found := local.lookup(lt.id, bind, false); !found {
		t.Fatal("a local task was not found")
	}
	if _, _, found := newServerState(f, nil, holdOrg, "gw-1", c.now).lookup(lt.id, bind, false); found {
		t.Fatal("another process found a local task")
	}
	f.down = true
	a.settle(k, bind, p.Action.ActionID, dispatch.Result{Class: dispatch.Held})
	if _, ok := a.heldAction(k); ok {
		t.Fatal("a hold was found with the server out of reach")
	}
	if a.newTask(bind, p, k, dispatch.Result{Class: dispatch.Held}, toolResult{}) != nil {
		t.Fatal("a task was made with the server out of reach")
	}
	if _, _, found := a.lookup(tk.id, bind, true); found {
		t.Fatal("a task was found with the server out of reach")
	}
}

// TestHR413_SessionsAreSharedAndOnlyTheirHashIsSent: a session opened on
// one replica is live on another with its binding; the server sees only
// the SHA-256 of the id; its use is written at most once a minute; an
// idle or ended session is gone; with the server out of reach a lookup is
// an error, not a miss.
func TestHR413_SessionsAreSharedAndOnlyTheirHashIsSent(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newFakeState(c.now)
	sa, sb := replicas(t, f, c)
	a := &serverSessions{st: sa, seen: map[[sha256.Size]byte]seenSession{}}
	b := &serverSessions{st: sb, seen: map[[sha256.Size]byte]seenSession{}}
	id, err := a.open(holdConn, holdInst, "jkt-1", holdRun, c.t.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, sent := range f.seen {
		if strings.Contains(string(sent), id) {
			t.Fatal("the session id was sent")
		}
	}
	sess, ok, err := b.get(id)
	if err != nil || !ok || sess.conn != holdConn || sess.instance != holdInst || sess.jkt != "jkt-1" || sess.run != holdRun {
		t.Fatalf("the other replica: %+v %v %v", sess, ok, err)
	}
	writes := len(f.seen)
	b.touch(id)
	if len(f.seen) != writes {
		t.Fatal("a touch within a minute was written")
	}
	c.t = c.t.Add(29 * time.Minute)
	b.touch(id)
	if len(f.seen) == writes {
		t.Fatal("a touch after a minute was not written")
	}
	c.t = c.t.Add(29 * time.Minute)
	if _, ok, _ := a.get(id); !ok {
		t.Fatal("a session used on the other replica went idle")
	}
	c.t = c.t.Add(sessionIdle)
	if _, ok, _ := a.get(id); ok {
		t.Fatal("an idle session was found")
	}
	id, _ = a.open(holdConn, holdInst, "jkt-1", holdRun, time.Time{})
	b.end(id)
	if _, ok, err := a.get(id); ok || err != nil {
		t.Fatalf("an ended session: %v %v", ok, err)
	}
	f.down = true
	if _, ok, err := a.get(id); ok || err == nil {
		t.Fatal("a lookup with the server out of reach was a miss, not an error")
	}
	if _, err := a.open(holdConn, holdInst, "jkt-1", holdRun, time.Time{}); err == nil || errors.Is(err, errSessionsFull) {
		t.Fatalf("open with the server out of reach: %v", err)
	}
}

// TestHR411_AnIdenticalHeldCallNamesTheSameTaskOnEveryReplica: a held
// call's task id is derived from the call, its action id and the shared
// broker key (G0 M15 D16), so an identical held call on another replica
// returns the working task; another action id, or another broker key
// after a rotation, names a new one.
func TestHR411_AnIdenticalHeldCallNamesTheSameTaskOnEveryReplica(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newFakeState(c.now)
	a, b := replicas(t, f, c)
	bind := binding{conn: holdConn, run: holdRun, instance: holdInst}
	p := heldIR(t, nil)
	k := actionKey(p.Action)
	held := dispatch.Result{Class: dispatch.Held}
	first := a.newTask(bind, p, k, held, toolResult{})
	again := b.newTask(bind, p, k, held, toolResult{})
	if first == nil || again == nil || again.id != first.id {
		t.Fatalf("the identical held call on another replica: %+v %+v", first, again)
	}
	other := heldIR(t, nil)
	if tk := b.newTask(bind, other, actionKey(other.Action), held, toolResult{}); tk == nil || tk.id == first.id {
		t.Fatal("another action id named the same task")
	}
	rotated := newServerState(f, newTestSealer(t), holdOrg, "gw-1", c.now)
	if tk := rotated.newTask(bind, p, k, held, toolResult{}); tk == nil || tk.id == first.id {
		t.Fatal("a rotated broker key named the same task")
	}
	done := a.newTask(bind, p, k, dispatch.Result{}, toolResult{})
	if done == nil || done.id == first.id || done.status != statusCompleted {
		t.Fatalf("a completed task: %+v", done)
	}
}

// TestHR412_ElicitationsAreSharedAndBounded: a relayed elicitation (D39)
// written on one replica is read on another with its binding and body;
// the server sees only the sealed body; writes are compare-and-set; it
// expires and is deleted; without a broker key it stays in its process.
func TestHR412_ElicitationsAreSharedAndBounded(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newFakeState(c.now)
	a, b := replicas(t, f, c)
	bind := binding{conn: holdConn, run: holdRun, instance: holdInst}
	k := key{0xe1}
	body := []byte(`{"question":"which account?"}`)
	for name, s := range map[string]holdStore{"memory": newStore(c.now), "server": a} {
		read := s
		if name == "server" {
			read = b
		}
		v, err := s.putElicitation(k, bind, body, c.t.Add(10*time.Minute), 0)
		if err != nil || v != 1 {
			t.Fatalf("%s put: %d %v", name, v, err)
		}
		if _, err := s.putElicitation(k, bind, body, c.t.Add(10*time.Minute), 0); !errors.Is(err, errStateConflict) {
			t.Fatalf("%s created twice: %v", name, err)
		}
		e, ok, err := read.getElicitation(k)
		if err != nil || !ok || e.binding != bind || !bytes.Equal(e.body, body) || e.version != 1 {
			t.Fatalf("%s get: %+v %v %v", name, e, ok, err)
		}
		if v, err := s.putElicitation(k, bind, body, e.expires, 1); err != nil || v != 2 {
			t.Fatalf("%s update: %d %v", name, v, err)
		}
		if _, err := read.deleteElicitation(k, 1); !errors.Is(err, errStateConflict) {
			t.Fatalf("%s delete of a stale version: %v", name, err)
		}
		if ok, err := read.deleteElicitation(k, 2); err != nil || !ok {
			t.Fatalf("%s delete: %v %v", name, ok, err)
		}
		if _, err := s.putElicitation(k, bind, body, c.t.Add(time.Minute), 0); err != nil {
			t.Fatal(err)
		}
		c.t = c.t.Add(time.Minute)
		if _, ok, _ := read.getElicitation(k); ok {
			t.Fatalf("%s an expired elicitation was found", name)
		}
	}
	for _, sent := range f.seen {
		if bytes.Contains(sent, []byte("which account")) {
			t.Fatal("the server saw an elicitation body")
		}
	}
	m := newStore(c.now)
	for i := range maxPerInstance {
		m.settle(key{byte(i), 2}, bind, "act", dispatch.Result{Class: dispatch.Held})
	}
	if _, err := m.putElicitation(k, bind, body, c.t.Add(time.Minute), 0); !errors.Is(err, errStateFull) {
		t.Fatalf("an elicitation past the instance bound: %v", err)
	}
	sent := len(f.seen)
	local := newServerState(f, nil, holdOrg, "gw-1", c.now)
	if _, err := local.putElicitation(k, bind, body, c.t.Add(time.Minute), 0); err != nil || len(f.seen) != sent {
		t.Fatalf("without a broker key: %v, sent %d", err, len(f.seen)-sent)
	}
}

// TestHR411_ARowRewrittenOnTheServerDoesNotOpen: a task's or an
// elicitation's sealed body binds its connection, run and instance (G0 M15
// D41). A row whose binding columns are rewritten on the server, under the
// same key, does not open on the gateway and is not found, even by the
// binding it was rewritten to.
func TestHR411_ARowRewrittenOnTheServerDoesNotOpen(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := newFakeState(c.now)
	a, b := replicas(t, f, c)
	bind := binding{conn: holdConn, run: holdRun, instance: holdInst}
	p := heldIR(t, nil)
	tk := a.newTask(bind, p, actionKey(p.Action), dispatch.Result{Class: dispatch.Held}, toolResult{})
	if tk == nil {
		t.Fatal("no task")
	}
	ek := key{0xe2}
	if _, err := a.putElicitation(ek, bind, []byte(`{}`), c.t.Add(10*time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	other := binding{conn: holdConn, run: ids.NewV7().String(), instance: holdInst}
	f.mu.Lock()
	for _, e := range f.m {
		e.RunId = other.run
	}
	f.mu.Unlock()
	if _, _, found := b.lookup(tk.id, other, true); found {
		t.Fatal("a task whose run was rewritten on the server was found")
	}
	if _, _, found := b.lookup(tk.id, bind, false); found {
		t.Fatal("a rewritten task was found by its first binding")
	}
	if b.cancel(tk.id, other) {
		t.Fatal("a rewritten task was canceled")
	}
	if _, found, err := b.getElicitation(ek); found || err != nil {
		t.Fatalf("an elicitation whose run was rewritten on the server: %v %v", found, err)
	}
}
