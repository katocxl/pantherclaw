// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"context"
	"testing"
	"time"
)

// TestHR505_TheRetryWaitIsJittered: the wait before the one retry is spread
// over [5 ms, 25 ms), and a canceled request does not wait.
// Covers: PN-011.1
func TestHR505_TheRetryWaitIsJittered(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 200 {
		d := busyJitter()
		if d < 5*time.Millisecond || d >= 25*time.Millisecond {
			t.Fatalf("jitter %v outside [5ms, 25ms)", d)
		}
		seen[d/time.Millisecond] = true
	}
	if len(seen) < 5 {
		t.Fatalf("the jitter is not spread: %d distinct milliseconds in 200 draws", len(seen))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := busyWait(ctx); err == nil {
		t.Fatal("a canceled request waited")
	}
}
