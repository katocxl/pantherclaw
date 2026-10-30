// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// The server-backed ownership (G0 M19 D202, D211): which run, through
// which connection, created each task and context is kept in the server's
// MCP state store as A2A_TASK and A2A_CONTEXT entries, so a task created
// through one gateway replica is served through another and a restart
// forgets nothing. A task's context id is sealed to the broker key the
// replicas share; the server never opens it. Entries carry M15's binding
// and the TASK bounds and lifetime (HR-411, HR-412); an entry past the
// bounds is not kept, so its task is refused later, as a forgotten one
// always was (fail closed).
//
// When the server cannot be asked, a task or context is not known and is
// refused (fail closed); a record that fails only leaves it unknown.
const (
	// stateTimeout bounds one state call.
	stateTimeout = 3 * time.Second
	// ownedTTL is an entry's lifetime; each answer naming the task or
	// context again renews it.
	ownedTTL = time.Hour
)

// Ownership is what the face remembers of the tasks and contexts each run
// created through each connection: in this process's memory, or on the
// server (WithServerState).
type ownership interface {
	record(w owner, task, context string)
	task(w owner, task string) (context string, ok bool)
	context(w owner, context string) bool
}

// StateClient is the part of GatewayService the server ownership calls.
type StateClient interface {
	PutMCPState(ctx context.Context, req *pb.PutMCPStateRequest) (*pb.PutMCPStateResponse, error)
	GetMCPState(ctx context.Context, req *pb.GetMCPStateRequest) (*pb.GetMCPStateResponse, error)
}

// Sealer seals and opens a task's context id with the gateway's broker
// key (*broker.Key).
type Sealer interface {
	SealState(aad, plaintext []byte) ([]byte, error)
	OpenState(aad, sealed []byte) ([]byte, error)
}

// WithServerState keeps the face's task and context ownership on the
// server (production wiring); org and gateway are the gateway's
// certificate identity, which the sealed bodies bind. Without a sealer
// the ownership stays in this process's memory, as before M19.
func (h *Handler) WithServerState(c StateClient, sealer Sealer, org, gateway string) *Handler {
	if c != nil && sealer != nil {
		h.owned = &serverOwned{c: c, seal: sealer, org: org, gateway: gateway, now: time.Now}
	}
	return h
}

type serverOwned struct {
	c            StateClient
	seal         Sealer
	org, gateway string
	now          func() time.Time
}

const (
	kindTask    = "A2A_TASK"
	kindContext = "A2A_CONTEXT"
)

func pbKind(kind string) pb.MCPStateKind {
	if kind == kindTask {
		return pb.MCPStateKind_MCP_STATE_KIND_A2A_TASK
	}
	return pb.MCPStateKind_MCP_STATE_KIND_A2A_CONTEXT
}

// ownedKey names an entry: the SHA-256 of the kind, the owner and the
// peer's id, each length-prefixed, so the same id answered to two runs is
// two entries and the id itself is never stored.
func (s *serverOwned) key(kind string, w owner, id string) []byte {
	h := sha256.New()
	for _, part := range []string{"pc.a2a_state.v1", kind, w.conn, w.run, id} {
		_ = binary.Write(h, binary.BigEndian, uint32(len(part))) //nolint:gosec // G115: parts are bounded ids
		h.Write([]byte(part))
	}
	return h.Sum(nil)
}

func (s *serverOwned) aad(kind string, k []byte, conn, run, instance string) []byte {
	return broker.StateAAD(s.org, s.gateway, kind, k, conn, run, instance)
}

func (s *serverOwned) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), stateTimeout)
}

// get returns a live entry that w owns.
func (s *serverOwned) get(kind string, w owner, id string) (*pb.MCPStateEntry, bool) {
	ctx, cancel := s.ctx()
	defer cancel()
	res, err := s.c.GetMCPState(ctx, &pb.GetMCPStateRequest{Kind: pbKind(kind), Key: s.key(kind, w, id)})
	e := res.GetEntry()
	if err != nil || e == nil || e.GetConnectionId() != w.conn || e.GetRunId() != w.run ||
		!s.now().Before(e.GetExpireTime().AsTime()) {
		return nil, false
	}
	return e, true
}

// put writes or renews w's entry; a failure only leaves it unknown.
func (s *serverOwned) put(kind string, w owner, id string, body func(k []byte) ([]byte, error)) {
	k := s.key(kind, w, id)
	var sealed []byte
	if body != nil {
		var err error
		if sealed, err = body(k); err != nil {
			return
		}
	}
	e := &pb.MCPStateEntry{
		Kind: pbKind(kind), Key: k, ConnectionId: w.conn, RunId: w.run, InstanceId: w.instance,
		SealedBody: sealed, ExpireTime: timestamppb.New(s.now().Add(ownedTTL)),
	}
	ctx, cancel := s.ctx()
	defer cancel()
	_, err := s.c.PutMCPState(ctx, &pb.PutMCPStateRequest{Entry: e})
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		return
	}
	// It exists: renew it, keeping its binding (the instance that wrote
	// it first).
	cur, ok := s.get(kind, w, id)
	if !ok {
		return
	}
	// The context of a task never changes: keep the stored body, sealed
	// to the stored binding.
	e.InstanceId, e.SealedBody = cur.GetInstanceId(), cur.GetSealedBody()
	_, _ = s.c.PutMCPState(ctx, &pb.PutMCPStateRequest{Entry: e, IfVersion: cur.GetVersion()})
}

func (s *serverOwned) record(w owner, task, context string) {
	if context != "" {
		s.put(kindContext, w, context, nil)
	}
	if task != "" {
		s.put(kindTask, w, task, func(k []byte) ([]byte, error) {
			return s.seal.SealState(s.aad(kindTask, k, w.conn, w.run, w.instance), []byte(context))
		})
	}
}

func (s *serverOwned) task(w owner, task string) (string, bool) {
	e, ok := s.get(kindTask, w, task)
	if !ok {
		return "", false
	}
	ctx, err := s.seal.OpenState(s.aad(kindTask, e.GetKey(), e.GetConnectionId(), e.GetRunId(), e.GetInstanceId()), e.GetSealedBody())
	if err != nil {
		return "", false
	}
	return string(ctx), true
}

func (s *serverOwned) context(w owner, context string) bool {
	_, ok := s.get(kindContext, w, context)
	return ok
}
