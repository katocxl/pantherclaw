// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
)

// TestM14_AuthZENIsCooperative: an authzen route is cooperative, like sdk
// and hook (PARTIAL unless a target verifier lifts it); an a2a route is
// mediated by the gateway (G0 M14 D4).
func TestM14_AuthZENIsCooperative(t *testing.T) {
	if !domain.ChannelAuthZEN.Cooperative() || domain.ChannelA2A.Cooperative() {
		t.Fatalf("authzen %v, a2a %v", domain.ChannelAuthZEN.Cooperative(), domain.ChannelA2A.Cooperative())
	}
}
