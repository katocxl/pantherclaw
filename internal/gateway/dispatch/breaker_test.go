// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

type reports struct {
	mu   sync.Mutex
	got  [][2]int32
	fail bool
}

func (r *reports) report(_ context.Context, _ string, unknown, total int32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, [2]int32{unknown, total})
	if r.fail {
		return errors.New("server unavailable")
	}
	return nil
}

func (r *reports) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func (r *reports) wait(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d reports, want %d", r.count(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func conn(revision int32, state string) *control.Connection {
	return &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c-1", Revision: revision, State: state}}
}

// TestHR078_TheBreakerOpensAtFiveUnknownsMakingHalfTheOutcomes: four
// unknowns, or five that are under half of the window's outcomes, keep it
// closed; five making half open it and report the counts once; outcomes
// older than the window no longer count.
func TestHR078_TheBreakerOpensAtFiveUnknownsMakingHalfTheOutcomes(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	r := &reports{}
	b := newBreaker(func() time.Time { return now }, r.report, pclog.Discard())
	c := conn(1, "ACTIVE")
	for range 6 {
		b.record(ctx, c, pb.Outcome_OUTCOME_ACCEPTED)
	}
	for range 5 {
		b.record(ctx, c, pb.Outcome_OUTCOME_UNKNOWN)
	}
	if b.open(ctx, c) {
		t.Fatal("5 unknowns out of 11 opened the circuit")
	}
	// A minute later the accepted ones have left the window.
	now = now.Add(BreakerWindow)
	for range 4 {
		b.record(ctx, c, pb.Outcome_OUTCOME_UNKNOWN)
	}
	if b.open(ctx, c) {
		t.Fatal("4 unknowns opened the circuit")
	}
	b.record(ctx, c, pb.Outcome_OUTCOME_FAILED)
	b.record(ctx, c, pb.Outcome_OUTCOME_UNKNOWN)
	if !b.open(ctx, c) {
		t.Fatal("5 unknowns out of 6 did not open the circuit")
	}
	r.wait(t, 1)
	r.mu.Lock()
	first := r.got[0]
	r.mu.Unlock()
	if first != [2]int32{5, 6} {
		t.Fatalf("reported %v", first)
	}
	b.open(ctx, c)
	time.Sleep(20 * time.Millisecond)
	if r.count() != 1 {
		t.Fatalf("an acknowledged report was sent again: %d", r.count())
	}
}

// TestHR078_AnOpenCircuitClosesOnlyWhenTheConnectionIsRestored: the circuit
// stays open while the connection is quarantined, even under a newer
// revision, and closes once it is active under a newer revision (a
// person's restore). An unacknowledged report is retried.
func TestHR078_AnOpenCircuitClosesOnlyWhenTheConnectionIsRestored(t *testing.T) {
	ctx := context.Background()
	r := &reports{fail: true}
	b := newBreaker(time.Now, r.report, pclog.Discard())
	c := conn(3, "ACTIVE")
	for range 5 {
		b.record(ctx, c, pb.Outcome_OUTCOME_UNKNOWN)
	}
	r.wait(t, 1)
	r.mu.Lock()
	r.fail = false
	r.mu.Unlock()
	// Each request asks the open circuit again, which retries the report
	// once the failed one has finished: the first ask may still find it in
	// flight (D133).
	deadline := time.Now().Add(5 * time.Second)
	for r.count() < 2 {
		if !b.open(ctx, c) {
			t.Fatal("not open")
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d reports, want 2", r.count())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !b.open(ctx, conn(3, "ACTIVE")) || !b.open(ctx, conn(4, "QUARANTINED")) {
		t.Fatal("the circuit closed before a restore")
	}
	if b.open(ctx, conn(5, "ACTIVE")) {
		t.Fatal("the circuit stayed open after a restore")
	}
}
