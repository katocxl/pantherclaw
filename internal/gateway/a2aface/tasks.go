// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"context"
	"sync"
)

// maxOwned bounds the task and context ids the face remembers; the oldest
// are forgotten first, and a forgotten id is refused like an unknown one
// (fail closed).
const maxOwned = 100_000

// owner is who may name a task or context: the run, through the
// connection, that created it (D31). instance is the agent instance that
// asked; it is not part of ownership, and the server store counts its
// bounds per instance (D211).
type owner struct {
	conn, run string
	instance  string
}

// who is the ownership part of w.
func (w owner) who() owner { return owner{conn: w.conn, run: w.run} }

type ownedKey struct {
	owner
	kind byte // 't' task, 'c' context
	id   string
}

// owned remembers which tasks and contexts each run created through each
// connection. Ids come from the peer's answers only, never from a request.
type owned struct {
	mu    sync.Mutex
	set   map[ownedKey]string // task → its context; context → ""
	order []ownedKey
	next  int
	max   int
}

func newOwned(limit int) *owned {
	if limit <= 0 {
		limit = maxOwned
	}
	return &owned{set: map[ownedKey]string{}, max: limit}
}

func (o *owned) add(k ownedKey, v string) {
	if _, ok := o.set[k]; ok {
		return
	}
	if len(o.order) < o.max {
		o.order = append(o.order, k)
	} else {
		delete(o.set, o.order[o.next])
		o.order[o.next] = k
		o.next = (o.next + 1) % o.max
	}
	o.set[k] = v
}

// record notes a task (and its context) the peer answered with for w.
func (o *owned) record(_ context.Context, w owner, task, context string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if context != "" {
		o.add(ownedKey{w.who(), 'c', context}, "")
	}
	if task != "" {
		o.add(ownedKey{w.who(), 't', task}, context)
	}
}

// task reports whether w created task, and its context.
func (o *owned) task(_ context.Context, w owner, task string) (context string, ok bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	context, ok = o.set[ownedKey{w.who(), 't', task}]
	return context, ok
}

// context reports whether w created context.
func (o *owned) context(_ context.Context, w owner, context string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, ok := o.set[ownedKey{w.who(), 'c', context}]
	return ok
}

// reserve keeps nothing: a process's memory is bounded by forgetting.
func (o *owned) reserve(context.Context, owner, string) (func(), error) { return func() {}, nil }
