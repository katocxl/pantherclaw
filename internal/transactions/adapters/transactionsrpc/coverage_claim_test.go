// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package transactionsrpc

import (
	"encoding/base64"
	"slices"
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR217_TheReceiptsCoverageClaimIsShown: a decision receipt's claim is
// read from its payload; a receipt without one, or whose body retention
// removed, shows none.
func TestHR217_TheReceiptsCoverageClaimIsShown(t *testing.T) {
	jws := func(payload string) string {
		return "h." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".s"
	}
	c := coverageOf(jws(`{"pap":{"coverage":{"v":1,"state":"PARTIAL","snapshot":"s1","scope":{},"snapshot_state":"ENFORCED",
		"lapsed":true,"reason":"expired","exclusions":["x1"]}}}`))
	if c == nil || c.GetState() != pantherclawv1.CoverageState_COVERAGE_STATE_PARTIAL || c.GetSnapshotId() != "s1" ||
		c.GetSnapshotState() != pantherclawv1.CoverageState_COVERAGE_STATE_ENFORCED || !c.GetLapsed() ||
		c.GetReason() != "expired" || !slices.Equal(c.GetExclusionIds(), []string{"x1"}) {
		t.Fatalf("claim %v", c)
	}
	for _, s := range []string{jws(`{"pap":{}}`), "removed", "a.!!.c"} {
		if c := coverageOf(s); c != nil {
			t.Errorf("%q: %v", s, c)
		}
	}
}
