// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestManifestStatesTheOrgsRetention: a pack states the retention in
// effect when it is built, from the org's revisions (F530, design decision
// 9): what a person set, a shortening only once it took effect, and the
// default otherwise.
func TestManifestStatesTheOrgsRetention(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	person := ids.NewV7()
	revs := []retention.Revision{
		// Defaults the system recorded.
		{Category: retention.Receipts, Number: 1, Days: 365, Created: now.Add(-60 * 24 * time.Hour), Effective: now.Add(-60 * 24 * time.Hour)},
		{Category: retention.Payloads, Number: 1, Days: 7, Created: now.Add(-60 * 24 * time.Hour), Effective: now.Add(-60 * 24 * time.Hour)},
		// A lengthening, in effect at once.
		{Category: retention.Receipts, Number: 2, Days: 730, SetBy: &person, Created: now.Add(-time.Hour), Effective: now.Add(-time.Hour)},
		// A shortening recorded yesterday: not in effect for six more days.
		{Category: retention.Payloads, Number: 2, Days: 3, SetBy: &person, Created: now.Add(-24 * time.Hour), Effective: now.Add(6 * 24 * time.Hour)},
	}
	want := []pack.Retention{
		{Category: "payloads", Days: 7, Source: "default"},
		{Category: "normalized_facts", Days: 90, Source: "default"},
		{Category: "receipts", Days: 730, Source: "policy receipts r2"},
		{Category: "approvals", Days: 365, Source: "default"},
		{Category: "security_audit", Days: 365, Source: "default"},
	}
	if got := retentionAt(revs, now); !slices.Equal(got, want) {
		t.Fatalf("retention %+v, want %+v", got, want)
	}
	if got := retentionAt(nil, now); got[2] != (pack.Retention{Category: "receipts", Days: 365, Source: "default"}) {
		t.Fatalf("no revisions: %+v", got)
	}
}
