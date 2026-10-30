// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// fakeState is GatewayService's MCP state for one gateway: compare-and-set
// versions, expiry, and every body sent.
type fakeState struct {
	now  func() time.Time
	mu   sync.Mutex
	m    map[string]*pb.MCPStateEntry
	down bool
	sent [][]byte
}

func newFakeState(now func() time.Time) *fakeState {
	return &fakeState{now: now, m: map[string]*pb.MCPStateEntry{}}
}

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
		return nil, connect.NewError(connect.CodeUnavailable, "down")
	}
	e := proto.Clone(r.GetEntry()).(*pb.MCPStateEntry)
	f.sent = append(f.sent, e.GetKey(), e.GetSealedBody())
	id := e.GetKind().String() + string(e.GetKey())
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
		return nil, connect.NewError(connect.CodeUnavailable, "down")
	}
	e, ok := f.live(r.GetKind().String() + string(r.GetKey()))
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, "MCP_STATE_NOT_FOUND")
	}
	return &pb.GetMCPStateResponse{Entry: proto.Clone(e).(*pb.MCPStateEntry)}, nil
}

func (f *fakeState) DeleteMCPState(_ context.Context, r *pb.DeleteMCPStateRequest) (*pb.DeleteMCPStateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, connect.NewError(connect.CodeUnavailable, "down")
	}
	id := r.GetKind().String() + string(r.GetKey())
	_, ok := f.live(id)
	delete(f.m, id)
	return &pb.DeleteMCPStateResponse{Deleted: ok}, nil
}

type testSealer struct{ k *pccrypto.SealPrivateKey }

func (s testSealer) SealState(aad, pt []byte) ([]byte, error) {
	return pccrypto.Seal(s.k.PublicKey(), []byte("pc.mcp_state.v1"), aad, pt)
}

func (s testSealer) OpenState(aad, sealed []byte) ([]byte, error) {
	return pccrypto.Open(s.k, []byte("pc.mcp_state.v1"), aad, sealed)
}

// TestA2AOwnershipIsSharedByEveryReplica: a task and context recorded
// through one gateway replica are known through another, only to the run
// and connection that created them, from any of the run's instances; the
// ids never reach the server in clear, and while the server cannot be
// asked nothing is known (fail closed) (G0 M19 D202, D211).
// Covers: PN-010.7
func TestA2AOwnershipIsSharedByEveryReplica(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	f := newFakeState(clock)
	k, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	sealer := testSealer{k: k}
	replica := func() *serverOwned {
		h := (&Handler{owned: newOwned(0), log: pclog.Discard()}).WithServerState(f, sealer, "org-1", "gw-1")
		s := h.owned.(*serverOwned)
		s.now = clock
		return s
	}
	a, b := replica(), replica()
	w := owner{conn: "conn-1", run: "run-1", instance: "inst-1"}

	a.record(ctx, w, "task-1", "ctx-1")
	if ctx, ok := b.task(ctx, owner{conn: "conn-1", run: "run-1", instance: "inst-2"}, "task-1"); !ok || ctx != "ctx-1" {
		t.Fatalf("task through the other replica = %q, %v", ctx, ok)
	}
	if !b.context(ctx, w, "ctx-1") {
		t.Fatal("context not known through the other replica")
	}
	for _, other := range []owner{{conn: "conn-1", run: "run-2"}, {conn: "conn-2", run: "run-1"}} {
		if _, ok := b.task(ctx, other, "task-1"); ok {
			t.Errorf("task known to %+v", other)
		}
		if b.context(ctx, other, "ctx-1") {
			t.Errorf("context known to %+v", other)
		}
	}
	for _, sent := range f.sent {
		for _, id := range []string{"task-1", "ctx-1", "run-1", "conn-1"} {
			if bytes.Contains(sent, []byte(id)) {
				t.Fatalf("%q reached the server in clear", id)
			}
		}
	}

	// Recording again renews the entries without changing the context.
	now = now.Add(50 * time.Minute)
	b.record(ctx, w, "task-1", "ctx-other")
	now = now.Add(50 * time.Minute)
	if ctx, ok := a.task(ctx, w, "task-1"); !ok || ctx != "ctx-1" {
		t.Fatalf("renewed task = %q, %v", ctx, ok)
	}
	// Unrenewed entries expire after their lifetime.
	a.record(ctx, w, "task-2", "")
	now = now.Add(ownedTTL)
	if _, ok := a.task(ctx, w, "task-2"); ok {
		t.Fatal("task known after its lifetime")
	}

	f.down = true
	if _, ok := a.task(ctx, w, "task-1"); ok {
		t.Fatal("task known while the server cannot be asked")
	}
	a.record(ctx, w, "task-3", "ctx-3") // only leaves it unknown
	f.down = false
	if _, ok := a.task(ctx, w, "task-3"); ok {
		t.Fatal("a failed record was remembered")
	}

	// Without a sealer the face keeps its own memory, as before M19.
	h := (&Handler{owned: newOwned(0)}).WithServerState(f, nil, "org-1", "gw-1")
	if _, ok := h.owned.(*owned); !ok {
		t.Fatalf("without a sealer the ownership is %T", h.owned)
	}
}

// TestA2ASendReservesItsTaskFirst: a send reserves its task's place before
// the peer sees it; while the server is unreachable or full the reservation
// is refused, and a released reservation leaves no entry (G0 M19 D218).
// Covers: PN-010.7
func TestA2ASendReservesItsTaskFirst(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	f := newFakeState(func() time.Time { return now })
	k, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	h := (&Handler{owned: newOwned(0), log: pclog.Discard()}).WithServerState(f, testSealer{k: k}, "org-1", "gw-1")
	s := h.owned.(*serverOwned)
	s.now = func() time.Time { return now }
	w := owner{conn: "conn-1", run: "run-1"}

	release, err := s.reserve(ctx, w, "msg-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.m) != 1 {
		t.Fatalf("%d entries while reserved, want 1", len(f.m))
	}
	release()
	release() // once
	if len(f.m) != 0 {
		t.Fatalf("%d entries after the release", len(f.m))
	}
	// A reservation is never a task anyone can name.
	if _, ok := s.task(ctx, w, reservedPrefix+"msg-1"); ok {
		t.Fatal("a released reservation reads as a task")
	}
	f.down = true
	if _, err := s.reserve(ctx, w, "msg-2"); err == nil {
		t.Fatal("reserved while the server cannot be asked")
	}
	if _, err := (&owned{}).reserve(ctx, w, "msg-3"); err != nil {
		t.Fatalf("memory reservation: %v", err)
	}
}

// TestA2AOnlyASendThatMayCreateATaskReserves: a send naming a task continues
// it and takes no place; other methods take none (G0 M19 D221).
// Covers: PN-010.7
func TestA2AOnlyASendThatMayCreateATaskReserves(t *testing.T) {
	send := func(task string) *wire.SendMessageRequest {
		return &wire.SendMessageRequest{Message: wire.Message{MessageID: "m1", TaskID: task}}
	}
	for _, c := range []struct {
		method string
		send   *wire.SendMessageRequest
		want   bool
	}{
		{wire.MethodSendMessage, send(""), true},
		{wire.MethodSendStreamingMessage, send(""), true},
		{wire.MethodSendMessage, send("task-1"), false},
		{wire.MethodSendStreamingMessage, send("task-1"), false},
		{wire.MethodGetTask, nil, false},
	} {
		if got := (call{method: c.method, send: c.send}).createsTask(); got != c.want {
			t.Errorf("%s with %+v: %v, want %v", c.method, c.send, got, c.want)
		}
	}
}
