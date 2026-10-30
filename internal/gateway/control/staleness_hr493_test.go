// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package control

import (
	"errors"
	"testing"
	"time"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR493_GatewayContainmentViewIsAtMostTwoSecondsOld (ADR-0040, the
// gateway containment view): the view serves at most MaxStaleness ≤ 2 s
// after its last message, and is stale (fail closed) one moment later.
// Covers: HR-493
func TestHR493_GatewayContainmentViewIsAtMostTwoSecondsOld(t *testing.T) {
	if MaxStaleness > 2*time.Second {
		t.Fatalf("MaxStaleness = %v, the bound is 2 s", MaxStaleness)
	}
	clk := &clock{now: time.Now()}
	k := newContainment(nil, pclog.Discard())
	k.now = clk.Now
	k.apply(msg(pb.ContainmentStateKind_CONTAINMENT_STATE_KIND_SNAPSHOT, 3, 1, false))
	clk.add(MaxStaleness)
	if _, err := k.Check(); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	clk.add(time.Millisecond)
	if _, err := k.Check(); !errors.Is(err, ErrStale) {
		t.Fatalf("past the bound: %v", err)
	}
}
