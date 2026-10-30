// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ratelimit

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// countingLimiter counts the Takes that reach a shared limiter and can be
// made to fail.
type countingLimiter struct {
	Limiter
	takes atomic.Int32
	fail  atomic.Bool
}

func (c *countingLimiter) Take(ctx context.Context, scope, key string, window time.Duration, n, limit int) (Decision, error) {
	c.takes.Add(1)
	if c.fail.Load() {
		return Decision{}, errors.New("store down")
	}
	return c.Limiter.Take(ctx, scope, key, window, n, limit)
}

func TestChunkSize(t *testing.T) {
	for limit, want := range map[int]int{1: 1, 15: 1, 16: 1, 32: 2, 600: 37, 6000: 375} {
		if got := ChunkSize(limit); got != want {
			t.Errorf("ChunkSize(%d) = %d, want %d", limit, got, want)
		}
	}
}

// TestHR490_LeasedReplicasStayWithinTheBound: N replicas leasing from one
// shared window admit at most limit + (N−1)·k between them (and here,
// with one shared counter, no more than the limit), at one shared write
// per chunk; a new window starts afresh and what was left of a chunk is
// never spent in it.
// Covers: HR-490, T-214
func TestHR490_LeasedReplicasStayWithinTheBound(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	shared := &countingLimiter{Limiter: NewMemory(clk)}
	const replicas, limit = 3, 160
	k := ChunkSize(limit)
	rs := make([]*Leased, replicas)
	for i := range rs {
		rs[i] = NewLeased(shared, clk)
	}
	allowed := 0
	for i := range 1000 {
		d, err := rs[i%replicas].Take(ctx, "api.org", "org-1", time.Minute, 1, limit)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed {
			allowed++
		} else if d.RetryAfter <= 0 || d.RetryAfter > time.Minute {
			t.Fatalf("RetryAfter = %v", d.RetryAfter)
		}
	}
	if bound := limit + (replicas-1)*k; allowed > bound || allowed > limit {
		t.Fatalf("%d allowed across %d replicas, bound %d (limit %d)", allowed, replicas, bound, limit)
	}
	if allowed < limit-(replicas-1)*k {
		t.Fatalf("%d allowed: chunks left on other replicas cost more than (N−1)·k", allowed)
	}
	// One shared write per chunk while chunks fit, plus the exact asks and
	// refusals at the end of the window, never one per call.
	if n := int(shared.takes.Load()); n > limit/k+3*replicas {
		t.Fatalf("%d shared takes for %d allowed calls (k = %d)", n, allowed, k)
	}

	// A refusal is remembered until the window ends: no further writes.
	before := shared.takes.Load()
	for range 50 {
		if d, _ := rs[0].Take(ctx, "api.org", "org-1", time.Minute, 1, limit); d.Allowed {
			t.Fatal("allowed past the limit")
		}
	}
	if shared.takes.Load() != before {
		t.Fatal("refusals within the window reached the shared store")
	}

	// The next window: chunks of the old one are not spent in it.
	clk.Advance(time.Minute)
	allowed = 0
	for i := range 1000 {
		if d, _ := rs[i%replicas].Take(ctx, "api.org", "org-1", time.Minute, 1, limit); d.Allowed {
			allowed++
		}
	}
	if allowed > limit || allowed < limit-(replicas-1)*k {
		t.Fatalf("the next window allowed %d (limit %d)", allowed, limit)
	}
}

// TestHR490_LeasedChunkExpiresWithItsWindow: a chunk leased near a
// window's end expires with that window; its rest is never carried over.
// Covers: HR-490
func TestHR490_LeasedChunkExpiresWithItsWindow(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 10, 30, 12, 0, 59, 0, time.UTC))
	shared := &countingLimiter{Limiter: NewMemory(clk)}
	l := NewLeased(shared, clk)
	if d, err := l.Take(ctx, "api.org", "o", time.Minute, 1, 32); err != nil || !d.Allowed || d.WindowLeft != time.Second {
		t.Fatalf("first take: %+v %v", d, err)
	}
	if d, _ := l.Take(ctx, "api.org", "o", time.Minute, 1, 32); !d.Allowed || shared.takes.Load() != 1 {
		t.Fatalf("the chunk's second event: %+v, %d shared takes", d, shared.takes.Load())
	}
	clk.Advance(time.Second)
	if d, _ := l.Take(ctx, "api.org", "o", time.Minute, 1, 32); !d.Allowed || shared.takes.Load() != 2 {
		t.Fatalf("a new window leases again: %+v, %d shared takes", d, shared.takes.Load())
	}
}

// TestHR490_LeasedStoreErrorIsReturned: a shared error with no live chunk
// is returned (the caller refuses, HR-376); a live chunk is still spent.
// Covers: HR-490
func TestHR490_LeasedStoreErrorIsReturned(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	shared := &countingLimiter{Limiter: NewMemory(clk)}
	l := NewLeased(shared, clk)
	shared.fail.Store(true)
	if d, err := l.Take(ctx, "api.org", "o", time.Minute, 1, 32); err == nil || d.Allowed {
		t.Fatalf("a store error: %+v %v", d, err)
	}
	shared.fail.Store(false)
	if d, err := l.Take(ctx, "api.org", "o", time.Minute, 1, 32); err != nil || !d.Allowed {
		t.Fatalf("after the store recovers: %+v %v", d, err)
	}
	shared.fail.Store(true)
	if d, err := l.Take(ctx, "api.org", "o", time.Minute, 1, 32); err != nil || !d.Allowed {
		t.Fatalf("the leased chunk's rest: %+v %v", d, err)
	}
	if d, err := l.Take(ctx, "api.org", "o", time.Minute, 1, 32); err == nil || d.Allowed {
		t.Fatalf("the chunk spent, the store down: %+v %v", d, err)
	}
}

// TestLeasedKeysAreBounded: past maxKeys, chunks are evicted.
func TestLeasedKeysAreBounded(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	l := NewLeased(NewMemory(clk), clk)
	l.maxKeys = 8
	for i := range 50 {
		if d, _ := l.Take(ctx, "s", string(rune('a'+i)), time.Minute, 1, 10); !d.Allowed {
			t.Fatal("a new key is refused")
		}
	}
	if n := len(l.chunks); n > 8 {
		t.Fatalf("%d chunks kept, bound 8", n)
	}
}

// stalledLimiter answers every Take after stall, with an error: a store
// that hangs until its statement timeout.
type stalledLimiter struct {
	stall time.Duration
	takes atomic.Int32
}

func (s *stalledLimiter) Take(ctx context.Context, _, _ string, _ time.Duration, _, _ int) (Decision, error) {
	s.takes.Add(1)
	select {
	case <-time.After(s.stall):
		return Decision{}, errors.New("statement timeout")
	case <-ctx.Done():
		return Decision{}, ctx.Err()
	}
}

// TestHR490_AStalledStoreDelaysEachCallByOneTimeoutAtMost (D215): callers
// of one key never queue behind each other's store calls; with the store
// stalled, every one of them gets the error (the caller refuses, or admits
// a safety call) within about one store timeout, from a single refill.
// Covers: HR-490
func TestHR490_AStalledStoreDelaysEachCallByOneTimeoutAtMost(t *testing.T) {
	const stall = 400 * time.Millisecond
	shared := &stalledLimiter{stall: stall}
	l := NewLeased(shared, nil)
	const callers = 8
	took := make(chan time.Duration, callers)
	start := time.Now()
	for range callers {
		go func() {
			_, err := l.Take(context.Background(), "api.credential", "key", time.Minute, 1, 100)
			if err == nil {
				t.Error("a stalled store admitted a call")
			}
			took <- time.Since(start)
		}()
	}
	for range callers {
		if d := <-took; d > 2*stall {
			t.Fatalf("a caller waited %v behind the others, one store timeout is %v", d, stall)
		}
	}
	if n := shared.takes.Load(); n != 1 {
		t.Fatalf("%d store calls for one refill, want 1", n)
	}
	// A caller whose own context ends stops waiting at once.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	go func() { _, _ = l.Take(context.Background(), "api.credential", "key2", time.Minute, 1, 100) }()
	time.Sleep(10 * time.Millisecond)
	begin := time.Now()
	if _, err := l.Take(ctx, "api.credential", "key2", time.Minute, 1, 100); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a waiter whose context ended: %v", err)
	}
	if d := time.Since(begin); d > stall {
		t.Fatalf("the waiter took %v after its context ended", d)
	}
}
