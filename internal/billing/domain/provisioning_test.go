// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "testing"

// Covers: F918, F921. SCIM and SAML are Enterprise (D406).
func TestSCIMAndSAMLAreEnterprise(t *testing.T) {
	for _, tc := range []struct {
		e    Edition
		want bool
	}{{Community, false}, {Team, false}, {Business, false}, {Enterprise, true}} {
		e := Entitlements{Edition: tc.e}
		if e.SCIM() != tc.want || e.SAML() != tc.want {
			t.Errorf("%s: SCIM %v, SAML %v, want %v", tc.e, e.SCIM(), e.SAML(), tc.want)
		}
	}
}
