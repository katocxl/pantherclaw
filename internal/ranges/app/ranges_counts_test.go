// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/rangerpc"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestListRangesCarriesStoredCounts (G0 M22 D58): a listed range has the
// counts of its stored results, and one with no stored result has none,
// which reads as not collected rather than zero.
func TestListRangesCarriesStoredCounts(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	counted := w.start(t, decl("RT-001", domain.TierCommunity, "boundary"))
	w.f.results[counted.ID] = []domain.Result{{Verdict: domain.Pass}, {Verdict: domain.Pass}, {Verdict: domain.Fail}, {Verdict: domain.Missing}}
	empty := ids.NewV7()
	w.f.ranges[empty] = domain.Range{ID: empty, Agent: w.agent, State: domain.Running}

	res, err := rangerpc.New(w.svc).ListRanges(w.ctx, &pantherclawv1.ListRangesRequest{PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*pantherclawv1.RangeCounts{}
	for _, r := range res.GetRanges() {
		got[r.GetId()] = r.GetCounts()
	}
	if len(got) != 2 {
		t.Fatalf("ranges: %v", got)
	}
	if c := got[counted.ID.String()]; c.GetPass() != 2 || c.GetFail() != 1 || c.GetMissing() != 1 {
		t.Fatalf("stored counts: %v", c)
	}
	if c := got[empty.String()]; c != nil {
		t.Fatalf("a range with no stored result has counts: %v", c)
	}
}
