// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
)

// TestHR030_ADisplayShowsOnlyTheBoundMembers (option B, founder decision
// 2026-10-13): a display shows a fact's value only through the members the
// approval binds, and never when or by whom it was observed, so a fact
// observed again gives the same display hash and a new bound value
// another. The bound digest does not depend on the order of the members.
func TestHR030_ADisplayShowsOnlyTheBoundMembers(t *testing.T) {
	hash := func(in domain.ActionInput) string {
		t.Helper()
		d, err := domain.RenderAction(in)
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return c.String()
	}
	in := refundInput(t, "")
	in.Bound = []domain.BoundFact{{Fact: "payments.charge.refundable", Subject: "payments.charge:ch_1", Member: "state", Value: "open"}}
	d, err := domain.RenderAction(in)
	if err != nil {
		t.Fatal(err)
	}
	if f := d.Facts[0]; f.Value != "state: open" || f.Provider != "" || f.ObservedAt != "" {
		t.Fatalf("fact line %+v", f)
	}
	first := hash(in)

	again := refundInput(t, "")
	again.Bound = in.Bound
	again.Facts[0].ObservedAt = again.Facts[0].ObservedAt.Add(time.Minute)
	again.Facts[0].ProviderID = uid("0192f3a0-0000-7000-8000-0000000000f2")
	if hash(again) != first {
		t.Fatal("a fact observed again changed the display")
	}
	moved := refundInput(t, "")
	moved.Bound = []domain.BoundFact{{Fact: "payments.charge.refundable", Subject: "payments.charge:ch_1", Member: "state", Value: "disputed"}}
	if hash(moved) == first {
		t.Fatal("a new bound value kept the display")
	}

	two := []domain.BoundFact{
		{Fact: "github.pull.head", Subject: "github.pull_request:acme/payments#7", Member: "sha", Value: "abc"},
		{Fact: "github.pull.head", Subject: "github.pull_request:acme/payments#7", Member: "base", Value: "main"},
	}
	reversed := slices.Clone(two)
	slices.Reverse(reversed)
	if domain.BoundFactsDigest(two) != domain.BoundFactsDigest(reversed) {
		t.Fatal("the bound digest depends on the order")
	}
	if domain.BoundFactsDigest(nil) == domain.BoundFactsDigest(two) {
		t.Fatal("no bound members digest like some")
	}
}
