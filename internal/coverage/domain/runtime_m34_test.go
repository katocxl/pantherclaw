// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "testing"

// TestHR760_TheRuntimeChannelIsCooperative: channel runtime is cooperative
// (the runtime's gateway could skip PantherClaw), so its coverage is
// PARTIAL like authzen's; the gateway-dispatched channels are not.
func TestHR760_TheRuntimeChannelIsCooperative(t *testing.T) {
	if !ChannelRuntime.Cooperative() || ChannelRuntime != "runtime" {
		t.Fatal("channel runtime is not cooperative")
	}
	for _, c := range []Channel{ChannelMCP, ChannelHTTP, ChannelA2A} {
		if c.Cooperative() {
			t.Errorf("%s is cooperative", c)
		}
	}
}
