// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// The server-backed ownership (G0 M19 D202, D211, D218): which run,
// through which connection, created each task and context is kept in the
// server's MCP state store as A2A_TASK and A2A_CONTEXT entries, so a task
// created through one gateway replica is served through another and a
// restart forgets nothing. A task's context id is sealed to the broker key
// the replicas share; the server never opens it. Entries carry M15's
// binding and the TASK bounds and lifetime (HR-411, HR-412), counted per
// caller (its agent instance, or its run without one).
//
// A send reserves a task's place before it reaches the peer: past the
// bounds, or while the server cannot be asked, the call is refused before
// the peer creates anything. Otherwise a task or context the server does
// not know is refused (fail closed); a record that fails is logged.
const (
	// stateTimeout bounds one state call.
	stateTimeout = 3 * time.Second
	// ownedTTL is an entry's lifetime; each answer naming the task or
	// context again renews it.
	ownedTTL = time.Hour
)

// ownership is what the face remembers of the tasks and contexts each run
// created through each connection: in this process's memory, or on the
// server (WithServerState). ctx is the agent's request.
type ownership interface {
	// reserve keeps a place for the task a send may create; release frees
	// it, before the answer is recorded.
	reserve(ctx context.Context, w owner, send string) (release func(), err error)
	record(ctx context.Context, w owner, task, context string)
	task(ctx context.Context, w owner, task string) (context string, ok bool)
	context(ctx context.Context, w owner, context string) bool
}

// StateClient is the part of GatewayService the server ownership calls.
type StateClient interface {
	PutMCPState(ctx context.Context, req *pb.PutMCPStateRequest) (*pb.PutMCPStateResponse, error)
	GetMCPState(ctx context.Context, req *pb.GetMCPStateRequest) (*pb.GetMCPStateResponse, error)
	DeleteMCPState(ctx context.Context, req *pb.DeleteMCPStateRequest) (*pb.DeleteMCPStateResponse, error)
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
		h.owned = &serverOwned{c: c, seal: sealer, org: org, gateway: gateway, now: time.Now, log: h.log}
	}
	return h
}

type serverOwned struct {
	c            StateClient
	seal         Sealer
	org, gateway string
	now          func() time.Time
	log          *slog.Logger
}

const (
	kindTask    = "A2A_TASK"
	kindContext = "A2A_CONTEXT"
	// reservedPrefix names a reservation's key; peer ids cannot hold NUL.
	reservedPrefix = "\x00reserved\x00"
)

func pbKind(kind string) pb.MCPStateKind {
	if kind == kindTask {
		return pb.MCPStateKind_MCP_STATE_KIND_A2A_TASK
	}
	return pb.MCPStateKind_MCP_STATE_KIND_A2A_CONTEXT
}

// key names an entry: the SHA-256 of the kind, the owner and the peer's
// id, each length-prefixed, so the same id answered to two runs is two
// entries and the id itself is never stored.
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

// get returns a live entry that w owns.
func (s *serverOwned) get(ctx context.Context, kind string, w owner, id string) (*pb.MCPStateEntry, bool) {
	ctx, cancel := context.WithTimeout(ctx, stateTimeout)
	defer cancel()
	res, err := s.c.GetMCPState(ctx, &pb.GetMCPStateRequest{Kind: pbKind(kind), Key: s.key(kind, w, id)})
	e := res.GetEntry()
	if err != nil || e == nil || e.GetConnectionId() != w.conn || e.GetRunId() != w.run ||
		!s.now().Before(e.GetExpireTime().AsTime()) {
		return nil, false
	}
	return e, true
}

// put writes w's entry, or renews it when it exists.
func (s *serverOwned) put(ctx context.Context, kind string, w owner, id, contextID string) error {
	ctx, cancel := context.WithTimeout(ctx, stateTimeout)
	defer cancel()
	k := s.key(kind, w, id)
	e := &pb.MCPStateEntry{
		Kind: pbKind(kind), Key: k, ConnectionId: w.conn, RunId: w.run, InstanceId: w.instance,
		ExpireTime: timestamppb.New(s.now().Add(ownedTTL)),
	}
	if kind == kindTask {
		sealed, err := s.seal.SealState(s.aad(kindTask, k, w.conn, w.run, w.instance), []byte(contextID))
		if err != nil {
			return err
		}
		e.SealedBody = sealed
	}
	_, err := s.c.PutMCPState(ctx, &pb.PutMCPStateRequest{Entry: e})
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		return err
	}
	// It exists: renew it, keeping its binding (the instance that wrote
	// it first) and its sealed context, which never changes.
	cur, ok := s.get(ctx, kind, w, id)
	if !ok {
		return err
	}
	e.InstanceId, e.SealedBody = cur.GetInstanceId(), cur.GetSealedBody()
	_, err = s.c.PutMCPState(ctx, &pb.PutMCPStateRequest{Entry: e, IfVersion: cur.GetVersion()})
	return err
}

func (s *serverOwned) reserve(ctx context.Context, w owner, send string) (func(), error) {
	id := reservedPrefix + send
	if err := s.put(ctx, kindTask, w, id, ""); err != nil {
		s.log.WarnContext(ctx, "gateway.a2a_state_refused", slog.String("connection_id", w.conn),
			slog.String("code", connect.CodeOf(err).String()), pclog.Err(err))
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			// The request may be over; the release still happens.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stateTimeout)
			defer cancel()
			if _, err := s.c.DeleteMCPState(ctx, &pb.DeleteMCPStateRequest{Kind: pbKind(kindTask), Key: s.key(kindTask, w, id)}); err != nil {
				s.log.WarnContext(ctx, "gateway.a2a_reservation_not_released", pclog.Err(err))
			}
		})
	}, nil
}

func (s *serverOwned) record(ctx context.Context, w owner, task, context string) {
	if context != "" {
		if err := s.put(ctx, kindContext, w, context, ""); err != nil {
			s.log.WarnContext(ctx, "gateway.a2a_context_not_kept", slog.String("connection_id", w.conn), pclog.Err(err))
		}
	}
	if task != "" {
		if err := s.put(ctx, kindTask, w, task, context); err != nil {
			s.log.WarnContext(ctx, "gateway.a2a_task_not_kept", slog.String("connection_id", w.conn), pclog.Err(err))
		}
	}
}

func (s *serverOwned) task(ctx context.Context, w owner, task string) (string, bool) {
	e, ok := s.get(ctx, kindTask, w, task)
	if !ok {
		return "", false
	}
	c, err := s.seal.OpenState(s.aad(kindTask, e.GetKey(), e.GetConnectionId(), e.GetRunId(), e.GetInstanceId()), e.GetSealedBody())
	if err != nil {
		return "", false
	}
	return string(c), true
}

func (s *serverOwned) context(ctx context.Context, w owner, context string) bool {
	_, ok := s.get(ctx, kindContext, w, context)
	return ok
}
