// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

func TestMemoryWindows(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 10, 21, 12, 0, 50, 0, time.UTC))
	m := NewMemory(clk)
	take := func(key string, n, limit int) Decision {
		t.Helper()
		d, err := m.Take(ctx, "s", key, time.Minute, n, limit)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if !take("a", 2, 3).Allowed || !take("a", 1, 3).Allowed {
		t.Fatal("within the limit")
	}
	d := take("a", 1, 3)
	if d.Allowed || d.RetryAfter != 10*time.Second {
		t.Fatalf("past the limit: %+v, want refused with 10s left", d)
	}
	if !take("b", 3, 3).Allowed {
		t.Fatal("another key has its own window")
	}
	if d, _ := m.Take(ctx, "other", "a", time.Minute, 1, 1); !d.Allowed {
		t.Fatal("another scope has its own window")
	}
	if take("c", 4, 3).Allowed {
		t.Fatal("more than the limit at once")
	}
	// A refused batch used nothing.
	if !take("c", 3, 3).Allowed {
		t.Fatal("a refused batch counted")
	}
	clk.Advance(10 * time.Second)
	if !take("a", 3, 3).Allowed {
		t.Fatal("a new window")
	}
}

// TestMemoryBound: past maxKeys, ended windows go first, so a current
// window survives.
func TestMemoryBound(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	m := NewMemory(clk)
	m.maxKeys = 3
	_, _ = m.Take(ctx, "s", "old", time.Second, 1, 1)
	clk.Advance(2 * time.Second)
	_, _ = m.Take(ctx, "s", "a", time.Minute, 1, 1)
	_, _ = m.Take(ctx, "s", "b", time.Minute, 1, 1)
	_, _ = m.Take(ctx, "s", "c", time.Minute, 1, 1)
	if len(m.windows) != 3 {
		t.Fatalf("%d windows kept, want 3", len(m.windows))
	}
	if d, _ := m.Take(ctx, "s", "a", time.Minute, 1, 1); d.Allowed {
		t.Fatal("a current window was reset")
	}
	// Full of current windows: a new key evicts only the oldest (a); b
	// and c keep their counts (D28).
	_, _ = m.Take(ctx, "s", "d", time.Minute, 1, 1)
	if len(m.windows) != 3 {
		t.Fatalf("%d windows kept, want 3", len(m.windows))
	}
	for _, k := range []string{"b", "c", "d"} {
		if d, _ := m.Take(ctx, "s", k, time.Minute, 1, 1); d.Allowed {
			t.Fatalf("%s's window was reset", k)
		}
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for d, want := range map[time.Duration]int{0: 1, time.Millisecond: 1, time.Second: 1, 1500 * time.Millisecond: 2, time.Minute: 60} {
		if got := RetryAfterSeconds(d); got != want {
			t.Errorf("RetryAfterSeconds(%v) = %d, want %d", d, got, want)
		}
	}
}

func TestStoreRefusesBadArguments(t *testing.T) {
	s := &Store{} // no pool: every case below returns before it
	ctx := context.Background()
	for name, f := range map[string]func() error{
		"scope":  func() error { _, err := s.Take(ctx, "Bad Scope", "k", time.Minute, 1, 1); return err },
		"key":    func() error { _, err := s.Take(ctx, "s", "", time.Minute, 1, 1); return err },
		"window": func() error { _, err := s.Take(ctx, "s", "k", 1500*time.Millisecond, 1, 1); return err },
		"long":   func() error { _, err := s.Take(ctx, "s", "k", 2*time.Hour, 1, 1); return err },
		"limit":  func() error { _, err := s.Take(ctx, "s", "k", time.Minute, 1, 0); return err },
	} {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if d, err := s.Take(ctx, "s", "k", time.Minute, 5, 4); err != nil || d.Allowed || d.RetryAfter <= 0 {
		t.Fatalf("more than the limit at once: %+v %v", d, err)
	}
}
