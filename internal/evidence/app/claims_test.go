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
	snap, agent, conn := ids.NewV7(), ids.NewV7(), ids.NewV7()
	scope := `"scope":{"agent":"` + agent.String() + `","connection":"` + conn.String() + `","operation":"github.pulls.merge"}`
	jws := func(payload string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
	}
	got := coverageClaims([]string{
		jws(`{"iat":1791720000,"pap":{"coverage":{"state":"ENFORCED","snapshot":"` + snap.String() + `",` + scope + `}}}`),
		jws(`{"pap":{"decision":"ALLOW"}}`),
		jws(`{"iat":1791720001,"pap":{"coverage":{"snapshot":"not-a-uuid",` + scope + `}}}`),
		"not a jws",
	})
	// A claim on an id that is not a snapshot still names its scope, whose
	// snapshots around the decision the bundle carries (T-089).
	want := []claimRef{
		{Snapshot: snap, At: time.Unix(1791720000, 0).UTC(), Agent: agent, Connection: conn, Operation: "github.pulls.merge"},
		{At: time.Unix(1791720001, 0).UTC(), Agent: agent, Connection: conn, Operation: "github.pulls.merge"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("claims %v, want %v", got, want)
	}
}
