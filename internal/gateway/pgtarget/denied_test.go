// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtarget_test

import (
	"net/netip"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget"
)

// TestHR330_InternalNeedsOperatorPrefix (D98, HR-077, HR-142): a public
// address is reachable; any other only for an internal endpoint and only
// inside a prefix the gateway's operator allowed, so loopback and
// link-local only when listed, and never on a gateway with no prefixes (a
// PantherClaw-hosted one); metadata never.
func TestHR330_InternalNeedsOperatorPrefix(t *testing.T) {
	none := []netip.Prefix(nil)
	tenNet := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	loop := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("169.254.0.0/16")}
	for _, c := range []struct {
		addr     string
		internal bool
		allowed  []netip.Prefix
		denied   bool
	}{
		{"8.8.8.8", false, none, false},
		{"8.8.8.8", true, none, false},
		{"10.0.0.5", false, none, true},
		{"10.0.0.5", true, none, true},
		{"127.0.0.1", true, none, true},
		{"10.0.0.5", true, tenNet, false},
		{"10.0.0.5", false, tenNet, true},
		{"127.0.0.1", true, tenNet, true},
		{"169.254.10.1", true, tenNet, true},
		{"127.0.0.1", true, loop, false},
		{"169.254.10.1", true, loop, false},
		{"169.254.169.254", true, loop, true},
		{"fd00:ec2::254", true, []netip.Prefix{netip.MustParsePrefix("fd00::/8")}, true},
		{"192.168.1.1", true, tenNet, true},
		{"::ffff:10.0.0.5", true, none, true},
	} {
		if got := pgtarget.Denied(netip.MustParseAddr(c.addr), c.internal, c.allowed); got != c.denied {
			t.Errorf("%s internal=%v allowed=%v: denied %v", c.addr, c.internal, c.allowed, got)
		}
	}
}
