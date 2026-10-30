// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// Leased is a Limiter that spends chunks leased from a shared Limiter (the
// Store) on this replica (G0 M19 D201, HR-490). A lease takes k =
// ChunkSize(limit) events of the key's shared window at once and spends
// them locally; the chunk expires when its window ends on the database's
// clock, so what is left of it is never spent in the next window. The
// shared window never admits more than limit, so across N replicas a
// window admits at most limit + (N−1)·k, at one write per k calls.
//
// When a whole chunk no longer fits, the replica asks for just the events
// at hand, so the last events of a window are not lost to chunk rounding.
// A refusal is remembered until the window ends: the shared count only
// grows within a window, so asking again could only be refused. A shared
// error is returned as it is, and the caller refuses the request (HR-376).
type Leased struct {
	shared  Limiter
	clock   clock.Clock
	maxKeys int

	mu     sync.Mutex
	chunks map[memKey]*chunk
}

// chunk is what this replica holds of one key's window.
type chunk struct {
	mu sync.Mutex
	// left events of the lease may be spent until end.
	left int
	end  time.Time
	// full is set when the shared window refused fullAt events: until end,
	// fullAt or more events are refused here.
	full   bool
	fullAt int
	// refill is the lease in flight, if any; mu is never held across it.
	refill *refill
}

// ChunkSize is the number of events one lease takes of a window with
// limit events: max(1, limit/16) (D201).
func ChunkSize(limit int) int { return max(1, limit/16) }

// NewLeased returns a Leased limiter over shared on clk (the system clock
// when nil).
func NewLeased(shared Limiter, clk clock.Clock) *Leased {
	if clk == nil {
		clk = clock.System{}
	}
	return &Leased{shared: shared, clock: clk, maxKeys: 100_000, chunks: map[memKey]*chunk{}}
}

// Take implements Limiter.
func (l *Leased) Take(ctx context.Context, scope, key string, window time.Duration, n, limit int) (Decision, error) {
	if n < 1 || n > limit {
		return l.shared.Take(ctx, scope, key, window, n, limit) // the shared limiter's answer or error
	}
	c := l.chunk(memKey{scope, key})
	for {
		c.mu.Lock()
		if d, ok := c.spend(l.clock.Now(), n); ok {
			c.mu.Unlock()
			return d, nil
		}
		if r := c.refill; r != nil {
			// One refill per key at a time: wait for it without holding the
			// chunk, then look again (D215). A waiter never queues behind
			// more than the refill in flight, so a stalled store delays
			// each call by at most one store timeout.
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return Decision{}, ctx.Err()
			case <-r.done:
			}
			if r.err != nil && !(isCtxErr(r.err) && ctx.Err() == nil) {
				return Decision{}, r.err
			}
			continue
		}
		r := &refill{done: make(chan struct{})}
		c.refill = r
		c.mu.Unlock()
		return l.lease(ctx, c, r, scope, key, window, n, limit)
	}
}

// refill is one lease of a chunk in flight; waiters share its outcome.
type refill struct {
	done chan struct{}
	err  error
}

// spend answers from the chunk alone, when it can: a remembered refusal,
// or events left of the lease. c.mu is held.
func (c *chunk) spend(now time.Time, n int) (Decision, bool) {
	if !now.Before(c.end) {
		c.left, c.full, c.fullAt = 0, false, 0 // the window ended
		return Decision{}, false
	}
	if c.full && n >= c.fullAt {
		return Decision{RetryAfter: c.end.Sub(now)}, true
	}
	if c.left >= n {
		c.left -= n
		return Decision{Allowed: true, WindowLeft: c.end.Sub(now)}, true
	}
	return Decision{}, false
}

// lease takes a chunk from the shared limiter for n events, without
// holding c.mu, and publishes the outcome to the waiters of r.
func (l *Leased) lease(ctx context.Context, c *chunk, r *refill, scope, key string, window time.Duration, n, limit int,
) (Decision, error) {
	// The chunk's end is measured from before the lease was asked for, so
	// it never outlives the shared window.
	now := l.clock.Now()
	k := min(max(ChunkSize(limit), n), limit)
	d, err := l.shared.Take(ctx, scope, key, window, k, limit)
	if err == nil && !d.Allowed && k > n {
		k = n
		d, err = l.shared.Take(ctx, scope, key, window, n, limit)
	}
	c.mu.Lock()
	defer func() {
		c.refill, r.err = nil, err
		close(r.done)
		c.mu.Unlock()
	}()
	switch {
	case err != nil:
		return Decision{}, err
	case !d.Allowed:
		c.left, c.end, c.full, c.fullAt = 0, now.Add(d.RetryAfter), true, n
		return d, nil
	}
	// A refusal of more events stays true within the window (c.full).
	c.left, c.end = k-n, now.Add(d.WindowLeft)
	return Decision{Allowed: true, WindowLeft: d.WindowLeft}, nil
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// chunk returns key's chunk, creating it. At most maxKeys chunks are kept:
// past the bound, expired chunks go first, then any one (losing what is
// left of a lease only refuses sooner, never admits more).
func (l *Leased) chunk(k memKey) *chunk {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c, ok := l.chunks[k]; ok {
		return c
	}
	if len(l.chunks) >= l.maxKeys {
		now := l.clock.Now()
		for key, c := range l.chunks {
			if c.mu.TryLock() {
				expired := !now.Before(c.end)
				c.mu.Unlock()
				if expired {
					delete(l.chunks, key)
				}
			}
		}
		for key := range l.chunks {
			if len(l.chunks) < l.maxKeys {
				break
			}
			delete(l.chunks, key)
		}
	}
	c := &chunk{}
	l.chunks[k] = c
	return c
}
