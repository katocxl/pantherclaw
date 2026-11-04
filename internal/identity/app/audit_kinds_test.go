// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import "testing"

// TestHR664_IdentityStateKinds: each instance closing state and issuer
// revision state keeps its old audit kind byte for byte, and no other
// state has one, so an unknown state is refused before any write (HR-664).
func TestHR664_IdentityStateKinds(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		got  map[string]string
		want map[string]string
	}{
		{"instanceClosedKinds", instanceClosedKinds, map[string]string{
			"REJECTED": "identity.instance_rejected", "REVOKED": "identity.instance_revoked",
		}},
		{"issuerRevisionKinds", issuerRevisionKinds, map[string]string{
			"PROPOSED": "identity.issuer_proposed", "ACTIVE": "identity.issuer_narrowed",
		}},
	} {
		if len(c.got) != len(c.want) {
			t.Errorf("%s has %d states, want %d", c.name, len(c.got), len(c.want))
		}
		for state, want := range c.want {
			if got := c.got[state]; got != want {
				t.Errorf("%s[%s] = %q, want %q", c.name, state, got, want)
			}
		}
		if _, ok := c.got["EXPIRED"]; ok {
			t.Errorf("%s has EXPIRED, want no kind", c.name)
		}
	}
}
