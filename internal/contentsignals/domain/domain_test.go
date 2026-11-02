// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestHR651_NoWordingClaimsSafety: what a person reads for no flags says what
// is known and nothing more, and every face the gateway cannot see into is
// listed as not inspected.
//
// Covers: F941
func TestHR651_NoWordingClaimsSafety(t *testing.T) {
	for _, s := range []string{NoKnownFlags, NotInspected, NotScanned} {
		l := strings.ToLower(s)
		if strings.Contains(l, "clean") || strings.Contains(l, "safe") {
			t.Errorf("%q claims safety", s)
		}
	}
	for _, says := range []string{"Hook", "SDK", "AuthZEN", "local", "delegated", "re-encoded", "split", "paraphrased"} {
		if !strings.Contains(NotScanned, says) {
			t.Errorf("the settings note does not say %q", says)
		}
	}
	if !slices.Equal(NotInspectedFaces, []string{"hook", "sdk", "authzen", "local", "delegated"}) {
		t.Fatalf("faces %v", NotInspectedFaces)
	}
}

// TestHR649_AFindingIsBounded: an unknown kind and a location that is empty,
// carries a line break or is over the bound are refused, and Pick keeps a
// finding of every kind within the cap.
//
// Covers: F937
func TestHR649_AFindingIsBounded(t *testing.T) {
	for _, f := range []Finding{
		{Kind: "nope", Location: "a"},
		{Kind: KindPIIEmail, Location: ""},
		{Kind: KindPIIEmail, Location: "a\nb"},
		{Kind: KindPIIEmail, Location: strings.Repeat("a", MaxLocation+1)},
	} {
		if f.Valid() {
			t.Errorf("%+v accepted", f)
		}
	}
	var in []Finding
	for i := range 40 {
		in = append(in, Finding{Kind: KindPIIEmail, Location: fmt.Sprintf("arg/%d", i)})
	}
	in = append(in, Finding{Kind: KindScanIncomplete, Location: IncompleteOverBound})
	out := Pick(in)
	if len(out) != MaxFindings || !slices.ContainsFunc(out, func(f Finding) bool { return f.Kind == KindScanIncomplete }) {
		t.Fatalf("%+v", out)
	}
}

// TestHR650_AReasonNamesWhyAScanStopped: WATCHING counts a large body apart
// from a stopped classifier.
//
// Covers: F939
func TestHR650_AReasonNamesWhyAScanStopped(t *testing.T) {
	if r := (Finding{Kind: KindScanIncomplete, Location: IncompleteOverBound}).Reason(); r != IncompleteOverBound {
		t.Fatalf("reason %q", r)
	}
	if r := (Finding{Kind: KindPIICard, Location: "arg"}).Reason(); r != KindPIICard {
		t.Fatalf("reason %q", r)
	}
}
