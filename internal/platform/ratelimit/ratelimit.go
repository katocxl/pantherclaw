// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ratelimit counts events per key in fixed windows (G0 M13 D8,
// D9). Two limiters share one interface:
//
//   - Store counts in PostgreSQL (pc.rate_counters), so a limit holds
//     across every replica (HR-376): automation inbound per source and
//     AuthZEN per enforcement point, signal transmitters and evidence
//     replays (G0 M19 D201). Its windows are aligned to the Unix epoch on
//     the database's clock. A caller that cannot reach the store refuses
//     the request (fail closed) and logs it.
//   - Memory counts on this replica only (tests, and the per-IP limits
//     documented as per replica, HR-494).
//
// Leased spends chunks leased from a Store on this replica, so the
// authenticated API's limits per organization and per credential (HR-375)
// hold across replicas at one write per chunk (G0 M19 D201, HR-490).
// Leases counts concurrent streams and waits across replicas (HR-491).
//
// Take adds n events to a key's window only when all of them fit, so a
// refused request never uses up the window.
package ratelimit

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// Decision is the answer to one Take.
type Decision struct {
	// Allowed is true when the events fit in the window and were counted.
	Allowed bool
	// RetryAfter is how long until the key's window ends (refusals only).
	RetryAfter time.Duration
	// WindowLeft is how long until the key's window ends (allowed only); a
	// leased chunk expires with it.
	WindowLeft time.Duration
}

// Limiter counts events per scope and key in fixed windows.
type Limiter interface {
	// Take adds n events to key's current window of length window if the
	// count stays at or below limit. An error means nothing is known; the
	// caller refuses the request.
	Take(ctx context.Context, scope, key string, window time.Duration, n, limit int) (Decision, error)
}

// RetryAfterSeconds is d in whole seconds, rounded up, at least 1: the
// value of a Retry-After header.
func RetryAfterSeconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	return max(s, 1)
}

// Memory is a Limiter on this replica only. Each key has its own window,
// aligned to the Unix epoch. At most maxKeys keys are kept: when the bound
// is reached, the keys whose windows started longest ago are evicted
// first, one at a time, so the bound never resets every window at once
// (G0 M13 D28).
type Memory struct {
	mu      sync.Mutex
	clock   clock.Clock
	maxKeys int
	windows map[memKey]*list.Element // of *memWindow
	order   *list.List               // oldest window first
}

type memKey struct{ scope, key string }

type memWindow struct {
	key   memKey
	end   time.Time
	count int
}

// NewMemory returns a Memory limiter on clk (the system clock when nil).
func NewMemory(clk clock.Clock) *Memory {
	if clk == nil {
		clk = clock.System{}
	}
	return &Memory{clock: clk, maxKeys: 100_000, windows: map[memKey]*list.Element{}, order: list.New()}
}

// Take implements Limiter; it never fails.
func (m *Memory) Take(_ context.Context, scope, key string, window time.Duration, n, limit int) (Decision, error) {
	now := m.clock.Now()
	if window <= 0 || n > limit {
		return Decision{RetryAfter: max(window, time.Second)}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey{scope, key}
	el, ok := m.windows[k]
	if !ok || !now.Before(el.Value.(*memWindow).end) {
		if ok {
			m.order.Remove(el)
			delete(m.windows, k)
		}
		for len(m.windows) >= m.maxKeys {
			oldest := m.order.Front()
			m.order.Remove(oldest)
			delete(m.windows, oldest.Value.(*memWindow).key)
		}
		start := now.Add(-time.Duration(now.UnixNano() % int64(window)))
		el = m.order.PushBack(&memWindow{key: k, end: start.Add(window)})
		m.windows[k] = el
	}
	w := el.Value.(*memWindow)
	if w.count+n > limit {
		return Decision{RetryAfter: w.end.Sub(now)}, nil
	}
	w.count += n
	return Decision{Allowed: true, WindowLeft: w.end.Sub(now)}, nil
}
