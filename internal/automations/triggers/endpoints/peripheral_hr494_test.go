// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package endpoints

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// TestHR494_TheInboundPerAddressLimitIsPerReplica (G0 M19 D201, R-66):
// the per-address limit before authentication is counted on each replica
// only (counting floods in the database would amplify them), so a second
// replica admits an address the first one refuses; each source's own rate
// is the shared store's (HR-376).
// Covers: HR-494
func TestHR494_TheInboundPerAddressLimitIsPerReplica(t *testing.T) {
	s := &Service{clock: clock.NewFake(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))}
	one, two := s.Receiver(), s.Receiver()
	const ip = "198.51.100.7"
	for i := range IPRateLimit {
		if !one.byIP.Allow(ip) {
			t.Fatalf("request %d refused within the limit", i+1)
		}
	}
	if one.byIP.Allow(ip) {
		t.Fatal("the replica admitted the address past its limit")
	}
	if !two.byIP.Allow(ip) {
		t.Fatal("another replica refused an address it never saw: the limit is not per replica")
	}
}
