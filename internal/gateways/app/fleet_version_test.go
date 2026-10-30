// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import "testing"

// TestHR470_UnparseableVersionIsUnknownAndNeverCompliant: anything but
// vMAJOR.MINOR.PATCH[-pre] reads as unknown, and an unknown version never
// meets a minimum (G0 M18 D151).
// Covers: PN-010.6
func TestHR470_UnparseableVersionIsUnknownAndNeverCompliant(t *testing.T) {
	minimum, ok := ParseVersion("v1.2.0")
	if !ok {
		t.Fatal("v1.2.0 does not parse")
	}
	for _, s := range []string{
		"", "dev", "devel", "1.2", "1.2.3.4", "v01.2.3", "1.2.3+build", "1.2.3-", "1.2.3-a..b",
		"1.2.x", "v-1.2.3", "99999999999999999999.0.0", "1.2.3-ü",
	} {
		v, ok := ParseVersion(s)
		if ok || v.Known() {
			t.Errorf("%q parsed as %v", s, v)
		}
		if v.String() != "unknown" {
			t.Errorf("%q shows as %q, want unknown", s, v.String())
		}
		if Compliant(v, minimum) {
			t.Errorf("unknown version %q counted as compliant", s)
		}
	}
}

func TestParseVersionAndCompare(t *testing.T) {
	order := []string{
		"v0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "v1.0.0", "1.0.1", "1.1.0", "2.0.0",
	}
	vs := make([]Version, len(order))
	for i, s := range order {
		v, ok := ParseVersion(s)
		if !ok {
			t.Fatalf("%q does not parse", s)
		}
		vs[i] = v
	}
	for i := range vs {
		for j := range vs {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := vs[i].Compare(vs[j]); got != want {
				t.Errorf("%s vs %s = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	if s := vs[1].String(); s != "v1.0.0-alpha" {
		t.Errorf("String = %q", s)
	}
	if !Compliant(vs[9], vs[8]) || Compliant(vs[7], vs[8]) || !Compliant(Version{}, Version{}) {
		t.Error("Compliant is wrong")
	}
}
