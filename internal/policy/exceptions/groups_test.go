// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exceptions

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR477_GroupDigestBindsTheCohortAndWhatIsWaived: the digest a group's
// change request binds changes with its cohort, the cohort's definition,
// rule, operations, owner and expiry, so a confirmation covers only the
// group as requested.
// Covers: F602
func TestHR477_GroupDigestBindsTheCohortAndWhatIsWaived(t *testing.T) {
	g := Group{
		OrgID: ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000c1"), ID: ids.NewV7(), CohortID: ids.NewV7(),
		BundleID: "org-policy", RuleID: "refunds", RuleDigest: make([]byte, 32), Operations: []string{"payments.refund.create"},
		Reason: "quarter end", OwnerID: ids.NewV7(), RequestedBy: ids.NewV7(), RequestedExpiry: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		CohortDigest: make([]byte, 32),
	}
	base, err := GroupDigest(g)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Group){
		"cohort":            func(x *Group) { x.CohortID = ids.NewV7() },
		"cohort definition": func(x *Group) { x.CohortDigest = append(make([]byte, 31), 1) },
		"rule":              func(x *Group) { x.RuleID = "other" },
		"operations":        func(x *Group) { x.Operations = []string{"payments.refund.create", "payments.refund.approve"} },
		"owner":             func(x *Group) { x.OwnerID = ids.NewV7() },
		"expiry":            func(x *Group) { x.RequestedExpiry = x.RequestedExpiry.Add(time.Hour) },
	} {
		x := g
		x.Operations = append([]string(nil), g.Operations...)
		change(&x)
		if d, err := GroupDigest(x); err != nil || d == base {
			t.Errorf("changing the %s left the digest as it was (%v)", name, err)
		}
	}
	// One agent's exception with the same ids never shares a group's digest.
	x := Exception{
		OrgID: g.OrgID, ID: g.ID, BundleID: g.BundleID, RuleID: g.RuleID, RuleDigest: g.RuleDigest, AgentID: g.CohortID,
		Operations: g.Operations, Reason: g.Reason, OwnerID: g.OwnerID, RequestedBy: g.RequestedBy, RequestedExpiry: g.RequestedExpiry,
	}
	if d, _ := Digest(x); d == base {
		t.Error("a group's digest equals an exception's")
	}
}

// TestGroupRequestBounds: a group request has the bounds of an exception
// request, and names a cohort.
// Covers: F602
func TestGroupRequestBounds(t *testing.T) {
	ok := GroupRequest{Rule: "refunds", Cohort: ids.NewV7(), Operations: []string{"payments.refund.create"}, Reason: "why", ExpiresIn: time.Hour}
	if !ok.valid() {
		t.Fatal("a valid group request was refused")
	}
	for name, r := range map[string]GroupRequest{
		"no cohort":    {Rule: ok.Rule, Operations: ok.Operations, Reason: ok.Reason, ExpiresIn: ok.ExpiresIn},
		"too long":     {Rule: ok.Rule, Cohort: ok.Cohort, Operations: ok.Operations, Reason: ok.Reason, ExpiresIn: MaxDuration + time.Second},
		"no reason":    {Rule: ok.Rule, Cohort: ok.Cohort, Operations: ok.Operations, Reason: " ", ExpiresIn: ok.ExpiresIn},
		"a prefix op":  {Rule: ok.Rule, Cohort: ok.Cohort, Operations: []string{"payments.*"}, Reason: ok.Reason, ExpiresIn: ok.ExpiresIn},
		"repeated ops": {Rule: ok.Rule, Cohort: ok.Cohort, Operations: []string{"a.b", "a.b"}, Reason: ok.Reason, ExpiresIn: ok.ExpiresIn},
	} {
		if r.valid() {
			t.Errorf("%s: accepted", name)
		}
	}
}
