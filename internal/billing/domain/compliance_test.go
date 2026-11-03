// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "testing"

// TestComplianceFrameworkEditions: OWASP and NIST on Team, the rest on
// Business, nothing on Community, and an unknown framework on nothing.
// Covers: F897
func TestComplianceFrameworkEditions(t *testing.T) {
	team := []string{"OWASP_ASI", "NIST_AI_RMF"}
	business := []string{"EU_AI_ACT_DEPLOYER", "ISO_42001", "SOC2"}
	for _, f := range team {
		for ed, want := range map[Edition]bool{Community: false, Team: true, Business: true, Enterprise: true} {
			if got := (Entitlements{Edition: ed}).ComplianceFramework(f); got != want {
				t.Errorf("%s on %s: %v", f, ed, got)
			}
		}
	}
	for _, f := range business {
		for ed, want := range map[Edition]bool{Community: false, Team: false, Business: true, Enterprise: true} {
			if got := (Entitlements{Edition: ed}).ComplianceFramework(f); got != want {
				t.Errorf("%s on %s: %v", f, ed, got)
			}
		}
	}
	if (Entitlements{Edition: Enterprise}).ComplianceFramework("DORA") {
		t.Error("an unknown framework is available")
	}
}
