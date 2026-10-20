// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"strings"
	"testing"
)

// TestM14ChannelsHaveNoMappingsYet: the authzen channel maps through the
// http and mcp mappings and never has its own, and an a2a mapping is
// refused until a2a mappings exist (G0 M14 D4, D9).
func TestM14ChannelsHaveNoMappingsYet(t *testing.T) {
	for ch, want := range map[Channel]string{ChannelAuthZEN: "authzen channel", ChannelA2A: "a2a mapping names a method"} {
		d := Definition{Mappings: []Mapping{{Channel: ch, Tool: "SendMessage", Route: "send"}}}
		if err := d.validateMapping(0); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", ch, err)
		}
	}
}
