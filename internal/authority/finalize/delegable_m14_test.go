// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
)

// TestM14_AuthZENDelegatedRefusedOnHeldConnection: the cooperative
// channels report the outcome delegated; authzen only through a connection
// whose credential PantherClaw does not hold, which is all an enforcement
// point may front; a channel the gateway dispatches on never does (HR-186,
// G0 M14 D4, D61).
func TestM14_AuthZENDelegatedRefusedOnHeldConnection(t *testing.T) {
	for _, c := range []struct {
		channel, access string
		want            bool
	}{
		{"hook", "none", true},
		{"sdk", "agent_held", true},
		{"sdk", "target_enforced", true},
		{"authzen", "agent_held", true},
		{"authzen", "target_enforced", true},
		{"authzen", "pantherclaw_held", false},
		{"authzen", "none", false},
		{"authzen", "", false},
		{"http", "agent_held", false},
		{"mcp", "agent_held", false},
		{"a2a", "pantherclaw_held", false},
		{"", "", false},
	} {
		if finalize.Delegable(c.channel, c.access) != c.want {
			t.Errorf("%q through %q: %v", c.channel, c.access, !c.want)
		}
	}
}

// TestHR186_DelegatedOnTargetEnforcedRecordsTargetEnforced: a delegated
// execution is recorded agent_held, or target_enforced when the
// connection's target verifies action tokens (HR-024, G0 M8 decision 9).
func TestHR186_DelegatedOnTargetEnforcedRecordsTargetEnforced(t *testing.T) {
	for access, want := range map[string]string{
		"target_enforced": "target_enforced", "agent_held": "agent_held",
		"none": "agent_held", "pantherclaw_held": "agent_held", "": "agent_held",
	} {
		if got := finalize.DelegatedAccess(access); got != want {
			t.Errorf("delegated through %q recorded %q, want %q", access, got, want)
		}
	}
}
