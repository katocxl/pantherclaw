// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package signals

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
)

// TestHR494_TheSignalPerAddressLimitIsPerReplica (G0 M19 D201, R-66): the
// per-address limit before a token is read is counted on each replica
// only, while each transmitter's budget is the shared store's whenever
// the service has a database.
// Covers: HR-494
func TestHR494_TheSignalPerAddressLimitIsPerReplica(t *testing.T) {
	s := &Service{clock: clock.NewFake(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))}
	one, two := s.Receiver(nil), s.Receiver(nil)
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
	if _, ok := one.limiter.(*ratelimit.Memory); !ok {
		t.Fatalf("without a database the transmitter limit is %T", one.limiter)
	}
}
