// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
)

// The in-memory holds, tasks and sessions (G0 M15 D14): the gateway's
// state before M15, for unit tests and for a gateway built without a
// control client. A restart forgets them, and replicas do not share them.

type memoryStore struct {
	clock func() time.Time
	mu    sync.Mutex
	holds map[key]hold
	tasks map[string]*task
	bytes int
}

func newStore(now func() time.Time) *memoryStore {
	return &memoryStore{clock: now, holds: map[key]hold{}, tasks: map[string]*task{}}
}

func (s *memoryStore) now() time.Time { return s.clock() }

// purgeLocked drops what expired.
func (s *memoryStore) purgeLocked(now time.Time) {
	for k, h := range s.holds {
		if !now.Before(h.expires) {
			delete(s.holds, k)
		}
	}
	for id, t := range s.tasks {
		if !now.Before(t.expires) {
			s.dropLocked(id)
		}
	}
}

func (s *memoryStore) dropLocked(id string) {
	if t, ok := s.tasks[id]; ok {
		s.bytes -= len(t.action.Canonical)
		delete(s.tasks, id)
	}
}

// fullLocked reports whether another entry for the instance, keeping
// extra bytes, would pass the bounds.
func (s *memoryStore) fullLocked(instance string, extra int) bool {
	if len(s.holds)+len(s.tasks) >= maxEntries || s.bytes+extra > maxTaskBytes {
		return true
	}
	n := 0
	for _, h := range s.holds {
		if h.binding.instance == instance {
			n++
		}
	}
	for _, t := range s.tasks {
		if t.binding.instance == instance {
			n++
		}
	}
	return n >= maxPerInstance
}

// heldAction returns the action id of an open hold on the same call.
func (s *memoryStore) heldAction(k key) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.holds[k]
	if !ok || !s.now().Before(h.expires) {
		return "", false
	}
	return h.action, true
}

// settle records what an answer means for the call's hold. A hold is
// remembered (within the bounds). An answer without a transaction decided
// nothing (the gateway refused before asking, or the Authority could not
// be asked), so an open hold stays. Anything else ends it.
func (s *memoryStore) settle(k key, b binding, action string, res dispatch.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case res.Class == dispatch.Held:
		now := s.now()
		s.purgeLocked(now)
		if _, ok := s.holds[k]; ok || !s.fullLocked(b.instance, 0) {
			s.holds[k] = hold{binding: b, action: action, expires: now.Add(holdTTL)}
		}
	case res.TransactionID != "":
		delete(s.holds, k)
	}
}

// newTask returns a task for a call's answer res. A held call's task is
// working and keeps the action to resubmit: the open one for the same
// call, or a new one. Any other answer (a 2025-11-25 task-augmented call
// that was not held) makes a completed task with result. It returns nil
// when the bounds are reached or no random id could be made.
func (s *memoryStore) newTask(b binding, a actionir.Parsed, k key, res dispatch.Result, result toolResult) *task {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil
	}
	held := res.Class == dispatch.Held
	if !held {
		a = actionir.Parsed{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.purgeLocked(now)
	for _, t := range s.tasks {
		if held && t.key == k && t.binding == b && t.status == statusWorking && t.action.Action.ActionID == a.Action.ActionID {
			cp := *t
			return &cp
		}
	}
	if s.fullLocked(b.instance, len(a.Canonical)) {
		return nil
	}
	t := &task{
		id: base64.RawURLEncoding.EncodeToString(raw[:]), binding: b, action: a, key: k,
		created: now, updated: now, expires: now.Add(holdTTL), status: statusWorking,
	}
	if !held {
		t.status, t.result = statusCompleted, &result
	}
	s.tasks[t.id] = t
	s.bytes += len(a.Canonical)
	cp := *t
	return &cp
}

// lookup returns a task of this binding; any other binding, or an expired
// task, is not found (HR-185). resubmit claims a working task for this
// poll, which then resubmits it and must call finish or release.
func (s *memoryStore) lookup(id string, b binding, resubmit bool) (snapshot task, claimed, found bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok || t.binding != b || !s.now().Before(t.expires) {
		return task{}, false, false
	}
	if resubmit && t.status == statusWorking && !t.busy {
		t.busy, claimed = true, true
	}
	return *t, claimed, true
}

// finish records a resubmission's answer: still held, or completed with
// the tool result (a tool error included). A task canceled meanwhile is
// answered from the poll's copy.
func (s *memoryStore) finish(snap task, res dispatch.Result, result toolResult) task {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[snap.id]
	if !ok {
		t = &snap
		t.status = statusCancelled
	}
	t.busy, t.updated = false, s.now()
	if res.Class != dispatch.Held {
		t.status, t.result = statusCompleted, &result
	}
	return *t
}

// release ends a claim that produced no answer.
func (s *memoryStore) release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tasks[id]; ok {
		t.busy = false
	}
}

// cancel forgets a task of this binding and the hold of its call, so the
// next identical call is a new action; it reports whether there was one.
func (s *memoryStore) cancel(id string, b binding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok || t.binding != b {
		return false
	}
	delete(s.holds, t.key)
	s.dropLocked(id)
	return true
}

type memorySessions struct {
	now func() time.Time
	mu  sync.Mutex
	// m is keyed by the SHA-256 of the session id.
	m map[[sha256.Size]byte]*session
}

func newSessions(now func() time.Time) *memorySessions {
	return &memorySessions{now: now, m: map[[sha256.Size]byte]*session{}}
}

// open starts a session ending at most 8 hours from now and never after
// runExpires, and returns its id.
func (s *memorySessions) open(conn, instance, jkt, run string, runExpires time.Time) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(raw[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.m {
		if !v.live(now) {
			delete(s.m, k)
		}
	}
	var mine [][sha256.Size]byte
	for k, v := range s.m {
		if v.instance == instance {
			mine = append(mine, k)
		}
	}
	if len(mine) >= maxSessionsPerInstance {
		oldest := mine[0]
		for _, k := range mine[1:] {
			if s.m[k].seen.Before(s.m[oldest].seen) {
				oldest = k
			}
		}
		delete(s.m, oldest)
	}
	if len(s.m) >= maxSessions {
		return "", errSessionsFull
	}
	expires := now.Add(sessionMax)
	if !runExpires.IsZero() && runExpires.Before(expires) {
		expires = runExpires
	}
	s.m[sessionKey(id)] = &session{conn: conn, instance: instance, jkt: jkt, run: run, seen: now, expires: expires}
	return id, nil
}

// get returns a live session.
func (s *memorySessions) get(id string) (session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[sessionKey(id)]
	if !ok || !v.live(s.now()) {
		return session{}, false, nil
	}
	return *v, true, nil
}

// touch records a verified request in the session.
func (s *memorySessions) touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[sessionKey(id)]; ok {
		v.seen = s.now()
	}
}

// end ends a session.
func (s *memorySessions) end(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, sessionKey(id))
}
