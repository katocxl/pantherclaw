// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"encoding/base64"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func TestCoverageClaimsAreTheReceiptsClaimsWithTheirDecisionTime(t *testing.T) {
	snap := ids.NewV7()
	jws := func(payload string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
	}
	got := coverageClaims([]string{
		jws(`{"iat":1791720000,"pap":{"coverage":{"state":"ENFORCED","snapshot":"` + snap.String() + `"}}}`),
		jws(`{"pap":{"decision":"ALLOW"}}`),
		jws(`{"pap":{"coverage":{"snapshot":"not-a-uuid"}}}`),
		"not a jws",
	})
	if want := []claimRef{{Snapshot: snap, At: time.Unix(1791720000, 0).UTC()}}; !slices.Equal(got, want) {
		t.Fatalf("claims %v, want %v", got, want)
	}
}
