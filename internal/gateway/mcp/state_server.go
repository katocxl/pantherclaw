// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// The server-backed holds, tasks and sessions (G0 M15 D12..D14, HR-411..
// 413): every replica of the gateway reads and writes the same entries
// through GatewayService, so a hold approved through one replica binds on
// another, a task created on one is polled on another, and a restart loses
// nothing. Entries are bound to (connection, run, instance) and checked on
// every read; a task's action and result are sealed to the gateway's
// broker key, which its replicas share, and the server never opens them.
// A session id never leaves the gateway: the entry's key is its SHA-256.
//
// When the server cannot be asked, a hold or task lookup is "not
// remembered" (a new action) and a session lookup answers 503.
const (
	// stateTimeout bounds one state call.
	stateTimeout = 3 * time.Second
	// touchEvery: a session's last use is written at most this often.
	touchEvery = time.Minute
)

// StateClient is the part of GatewayService the server store calls.
type StateClient interface {
	PutMCPState(ctx context.Context, req *pb.PutMCPStateRequest) (*pb.PutMCPStateResponse, error)
	GetMCPState(ctx context.Context, req *pb.GetMCPStateRequest) (*pb.GetMCPStateResponse, error)
	DeleteMCPState(ctx context.Context, req *pb.DeleteMCPStateRequest) (*pb.DeleteMCPStateResponse, error)
}

// Sealer seals and opens task and elicitation bodies with the gateway's
// broker key, and derives the key held tasks are named with (*broker.Key);
// nil keeps no task or elicitation on the server.
type Sealer interface {
	SealState(aad, plaintext []byte) ([]byte, error)
	OpenState(aad, sealed []byte) ([]byte, error)
	TaskIDKey(gateway string) ([]byte, error)
}

// WithServerState keeps the face's holds, tasks and sessions on the server
// (production wiring); org and gateway are the gateway's certificate
// identity, which the sealed bodies bind.
func (h *Handler) WithServerState(c StateClient, sealer Sealer, org, gateway string) *Handler {
	st := newServerState(c, sealer, org, gateway, time.Now)
	h.holds, h.sessions = st, &serverSessions{st: st, seen: map[[sha256.Size]byte]seenSession{}}
	return h
}

type serverState struct {
	c            StateClient
	seal         Sealer
	org, gateway string
	// local keeps the tasks of a gateway without a broker key in this
	// process's memory, as before M15: their bodies cannot be sealed, so
	// they are not shared. Holds and sessions are shared all the same.
	local *memoryStore
	clock func() time.Time

	// idKey names held tasks (D16), derived once.
	idOnce sync.Once
	idKey  []byte
}

func newServerState(c StateClient, sealer Sealer, org, gateway string, now func() time.Time) *serverState {
	s := &serverState{c: c, seal: sealer, org: org, gateway: gateway, clock: now}
	if sealer == nil {
		s.local = newStore(now)
	}
	return s
}

func (s *serverState) now() time.Time { return s.clock() }

func (s *serverState) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), stateTimeout)
}

func (s *serverState) get(kind pb.MCPStateKind, k []byte) (*pb.MCPStateEntry, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	res, err := s.c.GetMCPState(ctx, &pb.GetMCPStateRequest{Kind: kind, Key: k})
	if err != nil {
		return nil, err
	}
	return res.GetEntry(), nil
}

func (s *serverState) put(e *pb.MCPStateEntry, ifVersion int64) (int64, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	res, err := s.c.PutMCPState(ctx, &pb.PutMCPStateRequest{Entry: e, IfVersion: ifVersion})
	if err != nil {
		return 0, err
	}
	return res.GetVersion(), nil
}

func (s *serverState) del(kind pb.MCPStateKind, k []byte, ifVersion int64) (bool, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	res, err := s.c.DeleteMCPState(ctx, &pb.DeleteMCPStateRequest{Kind: kind, Key: k, IfVersion: ifVersion})
	return res.GetDeleted(), err
}

func isCode(err error, c connect.Code) bool { return err != nil && connect.CodeOf(err) == c }

func entryBinding(e *pb.MCPStateEntry) binding {
	return binding{conn: e.GetConnectionId(), run: e.GetRunId(), instance: e.GetInstanceId()}
}

// heldAction returns the action id of an open hold on the same call: one
// GetMCPState per tools/call, before the Authority is asked (D14).
func (s *serverState) heldAction(k key) (string, bool) {
	e, err := s.get(pb.MCPStateKind_MCP_STATE_KIND_HOLD, k[:])
	if err != nil || !s.now().Before(e.GetExpireTime().AsTime()) || e.GetActionId() == "" {
		return "", false
	}
	return e.GetActionId(), true
}

// settle records a hold (a new one, or the same call held again) or ends
// it, as the memory store does; a failure only leaves the hold unknown.
func (s *serverState) settle(k key, b binding, action string, res dispatch.Result) {
	switch {
	case res.Class == dispatch.Held:
		e := &pb.MCPStateEntry{
			Kind: pb.MCPStateKind_MCP_STATE_KIND_HOLD, Key: k[:], ConnectionId: b.conn, RunId: b.run, InstanceId: b.instance,
			ActionId: action, ExpireTime: timestamppb.New(s.now().Add(holdTTL)),
		}
		_, err := s.put(e, 0)
		if isCode(err, connect.CodeFailedPrecondition) {
			if cur, err := s.get(pb.MCPStateKind_MCP_STATE_KIND_HOLD, k[:]); err == nil {
				_, _ = s.put(e, cur.GetVersion())
			}
		}
	case res.TransactionID != "":
		_, _ = s.del(pb.MCPStateKind_MCP_STATE_KIND_HOLD, k[:], 0)
	}
}

// taskBody is a task's sealed body (D13): the canonical action to
// resubmit and the tool result once completed.
type taskBody struct {
	Action []byte      `json:"action"`
	Result *toolResult `json:"result"`
}

func taskKey(id string) []byte { k := sha256.Sum256([]byte(id)); return k[:] }

// aad is a sealed body's associated data (D13, D41).
func (s *serverState) aad(kind string, k []byte, b binding) []byte {
	return broker.StateAAD(s.org, s.gateway, kind, k, b.conn, b.run, b.instance)
}

// sealTask builds a task's entry with its sealed body.
func (s *serverState) sealTask(t *task) (*pb.MCPStateEntry, error) {
	if s.seal == nil {
		return nil, broker.ErrNoBroker
	}
	k := taskKey(t.id)
	pt, err := json.Marshal(taskBody{Action: t.action.Canonical, Result: t.result})
	if err != nil {
		return nil, err
	}
	sealed, err := s.seal.SealState(s.aad("TASK", k, t.binding), pt)
	if err != nil {
		return nil, err
	}
	return &pb.MCPStateEntry{
		Kind: pb.MCPStateKind_MCP_STATE_KIND_TASK, Key: k, ConnectionId: t.binding.conn, RunId: t.binding.run,
		InstanceId: t.binding.instance, ActionId: t.actionID, Status: t.status, Busy: t.busy, SealedBody: sealed,
		ExpireTime: timestamppb.New(t.expires),
	}, nil
}

// openTask turns an entry into a task; a body that does not open (the
// broker key rotated) is not found (D13).
func (s *serverState) openTask(id string, e *pb.MCPStateEntry) (task, bool) {
	if s.seal == nil {
		return task{}, false
	}
	pt, err := s.seal.OpenState(s.aad("TASK", e.GetKey(), entryBinding(e)), e.GetSealedBody())
	if err != nil {
		return task{}, false
	}
	var body taskBody
	if json.Unmarshal(pt, &body) != nil {
		return task{}, false
	}
	t := task{
		id: id, binding: entryBinding(e), actionID: e.GetActionId(), status: e.GetStatus(), busy: e.GetBusy(), result: body.Result,
		expires: e.GetExpireTime().AsTime(), updated: e.GetUpdateTime().AsTime(), version: e.GetVersion(),
	}
	t.created = t.expires.Add(-holdTTL)
	if len(body.Action) > 0 {
		a, err := actionir.Parse(body.Action)
		if err != nil {
			return task{}, false
		}
		t.action, t.key = a, actionKey(a.Action)
	}
	return t, true
}

// newTask stores a task for a call's answer, as the memory store makes
// one; nil when it cannot be stored (no broker key, the bounds, or the
// server out of reach), which only costs the agent the task.
func (s *serverState) newTask(b binding, a actionir.Parsed, k key, res dispatch.Result, result toolResult) *task {
	if s.local != nil {
		return s.local.newTask(b, a, k, res, result)
	}
	held := res.Class == dispatch.Held
	actionID := a.Action.ActionID
	if !held {
		a = actionir.Parsed{}
	}
	id, ok := s.taskID(held, k, actionID)
	if !ok || actionID == "" {
		return nil
	}
	now := s.now()
	t := &task{
		id: id, binding: b, action: a, key: k, actionID: actionID, created: now, updated: now, expires: now.Add(holdTTL),
		status: statusWorking,
	}
	if !held {
		t.status, t.result = statusCompleted, &result
	}
	e, err := s.sealTask(t)
	if err != nil {
		return nil
	}
	v, err := s.put(e, 0)
	switch {
	case err == nil:
		t.version = v
		return t
	case held && isCode(err, connect.CodeFailedPrecondition):
		// The same held call has its task already.
		if cur, err := s.get(pb.MCPStateKind_MCP_STATE_KIND_TASK, taskKey(id)); err == nil {
			if old, ok := s.openTask(id, cur); ok && old.binding == b && old.status == statusWorking && old.actionID == actionID {
				return &old
			}
		}
	}
	return nil
}

// lookup returns a task of this binding; another binding's, an expired
// one or one whose body does not open is not found (HR-185, HR-412). A
// claim is a compare-and-set of busy: a poll that loses the race only
// reads.
func (s *serverState) lookup(id string, b binding, resubmit bool) (snapshot task, claimed, found bool) {
	if s.local != nil {
		return s.local.lookup(id, b, resubmit)
	}
	e, err := s.get(pb.MCPStateKind_MCP_STATE_KIND_TASK, taskKey(id))
	if err != nil || entryBinding(e) != b || !s.now().Before(e.GetExpireTime().AsTime()) {
		return task{}, false, false
	}
	t, ok := s.openTask(id, e)
	if !ok {
		return task{}, false, false
	}
	if resubmit && t.status == statusWorking && !t.busy {
		// The body does not change: only busy.
		e.Busy = true
		if v, err := s.put(e, t.version); err == nil {
			t.version, t.busy, claimed = v, true, true
		}
	}
	return t, claimed, true
}

// finish records a resubmission's answer; a task canceled meanwhile is
// answered from the poll's copy.
func (s *serverState) finish(snap task, res dispatch.Result, result toolResult) task {
	if s.local != nil {
		return s.local.finish(snap, res, result)
	}
	e, err := s.get(pb.MCPStateKind_MCP_STATE_KIND_TASK, taskKey(snap.id))
	t, ok := task{}, false
	if err == nil && entryBinding(e) == snap.binding {
		t, ok = s.openTask(snap.id, e)
	}
	if !ok {
		snap.status, snap.busy, snap.updated = statusCancelled, false, s.now()
		if res.Class != dispatch.Held {
			snap.status, snap.result = statusCompleted, &result
		}
		return snap
	}
	t.busy, t.updated = false, s.now()
	if res.Class != dispatch.Held {
		t.status, t.result = statusCompleted, &result
	}
	if ne, err := s.sealTask(&t); err == nil {
		if v, err := s.put(ne, t.version); err == nil {
			t.version = v
		}
	}
	return t
}

// release ends a claim that produced no answer.
func (s *serverState) release(id string) {
	if s.local != nil {
		s.local.release(id)
		return
	}
	e, err := s.get(pb.MCPStateKind_MCP_STATE_KIND_TASK, taskKey(id))
	if err != nil || !e.GetBusy() {
		return
	}
	v := e.GetVersion()
	e.Busy = false
	_, _ = s.put(e, v)
}

// cancel forgets a task of this binding and the hold of its call.
func (s *serverState) cancel(id string, b binding) bool {
	if s.local != nil {
		t, _, found := s.local.lookup(id, b, false)
		if !found || !s.local.cancel(id, b) {
			return false
		}
		_, _ = s.del(pb.MCPStateKind_MCP_STATE_KIND_HOLD, t.key[:], 0)
		return true
	}
	k := taskKey(id)
	e, err := s.get(pb.MCPStateKind_MCP_STATE_KIND_TASK, k)
	if err != nil || entryBinding(e) != b {
		return false
	}
	// A body that does not open is not this binding's task (D41).
	t, ok := s.openTask(id, e)
	if !ok {
		return false
	}
	if t.action.Canonical != nil {
		_, _ = s.del(pb.MCPStateKind_MCP_STATE_KIND_HOLD, t.key[:], 0)
	}
	deleted, err := s.del(pb.MCPStateKind_MCP_STATE_KIND_TASK, k, e.GetVersion())
	return err == nil && deleted
}

// taskID is a new task's id (D16). A held call's is derived from the
// call and its action id with a key every replica shares, so an identical
// held call names the same task on any replica; any other is random. The
// entry's key is the SHA-256 of the id.
func (s *serverState) taskID(held bool, k key, actionID string) (string, bool) {
	if held {
		s.idOnce.Do(func() { s.idKey, _ = s.seal.TaskIDKey(s.gateway) })
		if len(s.idKey) == 0 {
			return "", false
		}
		m := hmac.New(sha256.New, s.idKey)
		_, _ = m.Write([]byte("pc.mcp_task.v1|" + hex.EncodeToString(k[:]) + "|" + actionID))
		return base64.RawURLEncoding.EncodeToString(m.Sum(nil)), true
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), true
}

// serverSessions are sessions on the server. seen remembers, per session
// this replica served, the entry and when its use was last written, so a
// session's use is written at most once a touchEvery (D14).
type serverSessions struct {
	st *serverState

	mu   sync.Mutex
	seen map[[sha256.Size]byte]seenSession
}

type seenSession struct {
	entry   *pb.MCPStateEntry
	written time.Time
}

func (s *serverSessions) remember(k [sha256.Size]byte, e *pb.MCPStateEntry, written time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.st.now()
	for x, v := range s.seen {
		if !now.Before(v.entry.GetExpireTime().AsTime()) {
			delete(s.seen, x)
		}
	}
	s.seen[k] = seenSession{entry: e, written: written}
}

func (s *serverSessions) open(conn, instance, jkt, run string, runExpires time.Time) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(raw[:])
	now := s.st.now()
	expires := now.Add(sessionMax)
	if !runExpires.IsZero() && runExpires.Before(expires) {
		expires = runExpires
	}
	k := sessionKey(id)
	e := &pb.MCPStateEntry{
		Kind: pb.MCPStateKind_MCP_STATE_KIND_SESSION, Key: k[:], ConnectionId: conn, RunId: run, InstanceId: instance, Jkt: jkt,
		ExpireTime: timestamppb.New(expires),
	}
	v, err := s.st.put(e, 0)
	if isCode(err, connect.CodeResourceExhausted) {
		return "", errSessionsFull
	} else if err != nil {
		return "", err
	}
	e.Version = v
	s.remember(k, e, now)
	return id, nil
}

func (s *serverSessions) get(id string) (session, bool, error) {
	k := sessionKey(id)
	e, err := s.st.get(pb.MCPStateKind_MCP_STATE_KIND_SESSION, k[:])
	if isCode(err, connect.CodeNotFound) {
		return session{}, false, nil
	} else if err != nil {
		return session{}, false, err
	}
	v := session{
		conn: e.GetConnectionId(), instance: e.GetInstanceId(), jkt: e.GetJkt(), run: e.GetRunId(),
		seen: e.GetUpdateTime().AsTime(), expires: e.GetExpireTime().AsTime(),
	}
	if !v.live(s.st.now()) {
		return session{}, false, nil
	}
	s.mu.Lock()
	written := s.seen[k].written
	s.mu.Unlock()
	if written.IsZero() || v.seen.After(written) {
		written = v.seen
	}
	s.remember(k, e, written)
	return v, true, nil
}

func (s *serverSessions) touch(id string) {
	k := sessionKey(id)
	now := s.st.now()
	s.mu.Lock()
	v, ok := s.seen[k]
	s.mu.Unlock()
	if !ok || now.Sub(v.written) < touchEvery {
		return
	}
	e := v.entry
	ver, err := s.st.put(e, e.GetVersion())
	if isCode(err, connect.CodeFailedPrecondition) {
		// Another replica wrote it: write over its version once.
		cur, gerr := s.st.get(pb.MCPStateKind_MCP_STATE_KIND_SESSION, k[:])
		if gerr != nil {
			return
		}
		e = cur
		ver, err = s.st.put(cur, cur.GetVersion())
	}
	if err == nil {
		e.Version = ver
		s.remember(k, e, now)
	}
}

func (s *serverSessions) end(id string) {
	k := sessionKey(id)
	_, _ = s.st.del(pb.MCPStateKind_MCP_STATE_KIND_SESSION, k[:], 0)
	s.mu.Lock()
	delete(s.seen, k)
	s.mu.Unlock()
}

// putElicitation writes a relayed elicitation, its body sealed with the
// kind in the associated data (D39, D13). Without a broker key it stays
// in this process, as tasks do.
func (s *serverState) putElicitation(k key, b binding, body []byte, expires time.Time, ifVersion int64) (int64, error) {
	if s.local != nil {
		return s.local.putElicitation(k, b, body, expires, ifVersion)
	}
	sealed, err := s.seal.SealState(s.aad("ELICITATION", k[:], b), body)
	if err != nil {
		return 0, err
	}
	v, err := s.put(&pb.MCPStateEntry{
		Kind: pb.MCPStateKind_MCP_STATE_KIND_ELICITATION, Key: k[:], ConnectionId: b.conn, RunId: b.run, InstanceId: b.instance,
		SealedBody: sealed, ExpireTime: timestamppb.New(expires),
	}, ifVersion)
	switch {
	case isCode(err, connect.CodeFailedPrecondition):
		return 0, errStateConflict
	case isCode(err, connect.CodeResourceExhausted):
		return 0, errStateFull
	}
	return v, err
}

// getElicitation returns a live relayed elicitation; one whose body does
// not open (the broker key rotated) is not found.
func (s *serverState) getElicitation(k key) (elicitation, bool, error) {
	if s.local != nil {
		return s.local.getElicitation(k)
	}
	e, err := s.get(pb.MCPStateKind_MCP_STATE_KIND_ELICITATION, k[:])
	if isCode(err, connect.CodeNotFound) {
		return elicitation{}, false, nil
	} else if err != nil {
		return elicitation{}, false, err
	}
	if !s.now().Before(e.GetExpireTime().AsTime()) {
		return elicitation{}, false, nil
	}
	body, oerr := s.seal.OpenState(s.aad("ELICITATION", k[:], entryBinding(e)), e.GetSealedBody())
	if oerr == nil {
		return elicitation{binding: entryBinding(e), body: body, version: e.GetVersion(), expires: e.GetExpireTime().AsTime()}, true, nil
	}
	// A body that does not open (the broker key rotated) is not found.
	return elicitation{}, false, nil
}

// deleteElicitation deletes a relayed elicitation.
func (s *serverState) deleteElicitation(k key, ifVersion int64) (bool, error) {
	if s.local != nil {
		return s.local.deleteElicitation(k, ifVersion)
	}
	deleted, err := s.del(pb.MCPStateKind_MCP_STATE_KIND_ELICITATION, k[:], ifVersion)
	if isCode(err, connect.CodeFailedPrecondition) {
		return false, errStateConflict
	}
	return deleted, err
}
