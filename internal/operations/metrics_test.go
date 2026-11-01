// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package operations

import (
	"strconv"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
)

// TestF301_ACutOfOwnersKeepsUnownedAndCountsTheRest: past the cap "unowned"
// and the largest owners stay, and the routes of the others still add up.
// Covers: F301
func TestF301_ACutOfOwnersKeepsUnownedAndCountsTheRest(t *testing.T) {
	owners := []dbq.MetricBypassRoutesByOwnerRow{{Owner: "unowned", N: 1}}
	for i := range MaxOwners {
		owners = append(owners, dbq.MetricBypassRoutesByOwnerRow{Owner: strconv.Itoa(i), N: 2})
	}
	const total = 1 + 2*MaxOwners + 5
	got := ownerSamples(owners, total)
	if len(got) != MaxOwners+1 || got[0].dimension != "unowned" {
		t.Fatalf("%d samples, first %+v", len(got), got[0])
	}
	sum, last := 0.0, got[len(got)-1]
	for _, s := range got {
		sum += s.value
	}
	if last.dimension != OwnersOther || last.value != 7 || sum != total {
		t.Errorf("last %+v, sum %v of %d", last, sum, total)
	}
	if got := ownerSamples(owners[:3], 5); len(got) != 3 {
		t.Errorf("no cut: %+v", got)
	}
	if got := ownerSamples(nil, 0); len(got) != 1 || !got[0].collected || got[0].value != 0 {
		t.Errorf("no routes: %+v", got)
	}
}
