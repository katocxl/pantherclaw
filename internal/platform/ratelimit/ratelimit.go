// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ratelimit counts events per key in fixed windows (G0 M13 D8,
// D9). Two limiters share one interface:
//
//   - Store counts in PostgreSQL (pc.rate_counters), so a limit holds
//     across every replica (HR-376): automation inbound per source and
//     AuthZEN per enforcement point. Its windows are aligned to the Unix
//     epoch on the database's clock. A caller that cannot reach the store
//     refuses the request (fail closed) and logs it.
//   - Memory counts on this replica only: the authenticated API's limits
//     per organization and per credential (HR-375), which are documented
//     as per replica.
//
// Take adds n events to a key's window only when all of them fit, so a
// refused request never uses up the window.
package ratelimit

import (
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

// retryAfter is the time left in now's epoch-aligned window.
func retryAfter(now time.Time, window time.Duration) time.Duration {
	return window - time.Duration(now.UnixNano()%int64(window))
}

// Memory is a Limiter on this replica only. Each key has its own window,
// aligned to the Unix epoch; at most maxKeys keys are kept, and windows
// that ended are dropped first when the bound is reached, so one key's
// window is never reset by others while it is current.
type Memory struct {
	mu      sync.Mutex
	clock   clock.Clock
	maxKeys int
	windows map[memKey]*memWindow
}

type memKey struct{ scope, key string }

type memWindow struct {
	end   time.Time
	count int
}

// NewMemory returns a Memory limiter on clk (the system clock when nil).
func NewMemory(clk clock.Clock) *Memory {
	if clk == nil {
		clk = clock.System{}
	}
	return &Memory{clock: clk, maxKeys: 100_000, windows: map[memKey]*memWindow{}}
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
	w, ok := m.windows[k]
	if !ok || !now.Before(w.end) {
		if !ok && len(m.windows) >= m.maxKeys {
			m.sweep(now)
		}
		start := now.Add(-time.Duration(now.UnixNano() % int64(window)))
		w = &memWindow{end: start.Add(window)}
		m.windows[k] = w
	}
	if w.count+n > limit {
		return Decision{RetryAfter: w.end.Sub(now)}, nil
	}
	w.count += n
	return Decision{Allowed: true}, nil
}

// sweep drops windows that ended; if every window is current, it drops
// them all (the bound wins over exactness, as in httpx.Limiter).
func (m *Memory) sweep(now time.Time) {
	for k, w := range m.windows {
		if !now.Before(w.end) {
			delete(m.windows, k)
		}
	}
	if len(m.windows) >= m.maxKeys {
		clear(m.windows)
	}
}
