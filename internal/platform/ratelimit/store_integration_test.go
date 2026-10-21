// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package ratelimit_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
)

// TestHR376_SharedCounterHoldsAcrossReplicas: two replicas (two pools)
// counting one key concurrently admit exactly the limit between them; a
// refused batch adds nothing; other keys and scopes are separate.
func TestHR376_SharedCounterHoldsAcrossReplicas(t *testing.T) {
	d := dbtest.New(t)
	stores := []*ratelimit.Store{ratelimit.NewStore(d.AppPool(t)), ratelimit.NewStore(d.AppPool(t))}
	ctx := context.Background()
	key := ids.NewV7().String()
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			dec, err := stores[i%2].Take(ctx, "test.shared", key, time.Hour, 1, 25)
			if err != nil {
				t.Error(err)
				return
			}
			if dec.Allowed {
				allowed.Add(1)
			} else if dec.RetryAfter <= 0 || dec.RetryAfter > time.Hour {
				t.Errorf("RetryAfter = %v", dec.RetryAfter)
			}
		})
	}
	wg.Wait()
	if n := allowed.Load(); n != 25 {
		t.Fatalf("%d of 40 allowed across two replicas, want 25", n)
	}
	other := ids.NewV7().String()
	if dec, err := stores[0].Take(ctx, "test.shared", other, time.Hour, 3, 4); err != nil || !dec.Allowed {
		t.Fatalf("another key: %+v %v", dec, err)
	}
	if dec, err := stores[1].Take(ctx, "test.shared", other, time.Hour, 2, 4); err != nil || dec.Allowed {
		t.Fatalf("a batch past the limit: %+v %v", dec, err)
	}
	if dec, err := stores[1].Take(ctx, "test.shared", other, time.Hour, 1, 4); err != nil || !dec.Allowed {
		t.Fatalf("the refused batch counted: %+v %v", dec, err)
	}
	if dec, err := stores[0].Take(ctx, "test.other", key, time.Hour, 1, 1); err != nil || !dec.Allowed {
		t.Fatalf("another scope: %+v %v", dec, err)
	}
}

// TestHR376_CounterErrorIsReported: a store that cannot count returns an
// error, which callers turn into a refusal.
func TestHR376_CounterErrorIsReported(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	s := ratelimit.NewStore(p)
	p.Close()
	if dec, err := s.Take(context.Background(), "test.closed", "k", time.Minute, 1, 10); err == nil || dec.Allowed {
		t.Fatalf("a closed pool: %+v %v", dec, err)
	}
}

// TestRateCountersJanitor removes windows older than two hours only.
func TestRateCountersJanitor(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	if _, err := ratelimit.NewStore(p).Take(ctx, "test.janitor", "now", time.Minute, 1, 1); err != nil {
		t.Fatal(err)
	}
	d.AdminExec(t, `INSERT INTO pc.rate_counters (scope, key, window_start, count) VALUES ('test.janitor', 'old', now() - interval '3 hours', 1)`)
	n, err := ratelimit.Clean(ctx, p)
	if err != nil || n != 1 {
		t.Fatalf("Clean = %d, %v; want 1", n, err)
	}
	var left int
	d.AdminQueryRow(t, `SELECT count(*) FROM pc.rate_counters WHERE scope = 'test.janitor'`, nil, &left)
	if left != 1 {
		t.Fatalf("%d windows left, want the current one", left)
	}
}
