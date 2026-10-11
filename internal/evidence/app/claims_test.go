// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"encoding/base64"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func TestClaimedSnapshotsAreTheReceiptsCoverageClaims(t *testing.T) {
	snap := ids.NewV7()
	jws := func(payload string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
	}
	got := claimedSnapshots([]string{
		jws(`{"pap":{"coverage":{"state":"ENFORCED","snapshot":"` + snap.String() + `"}}}`),
		jws(`{"pap":{"decision":"ALLOW"}}`),
		jws(`{"pap":{"coverage":{"snapshot":"not-a-uuid"}}}`),
		"not a jws",
	})
	if !slices.Equal(got, []ids.UUID{snap}) {
		t.Fatalf("claimed snapshots %v, want %v", got, snap)
	}
}
