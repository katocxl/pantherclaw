// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM28_ThreatMapReadRoles: threatmap.read and the roles that hold it,
// exactly (G0 M28 D722, D722a): the roles that read compliance coverage or
// detections, and the Investigator for technique_coverage (D726).
// Covers: F960, HR-686
func TestM28_ThreatMapReadRoles(t *testing.T) {
	p := domain.PermThreatMapRead
	if !p.Known() || !p.Declarable() || p.HumanOnly() {
		t.Fatalf("known=%v declarable=%v human-only=%v", p.Known(), p.Declarable(), p.HumanOnly())
	}
	var got []domain.RoleName
	for _, r := range domain.Roles() {
		if r.Has(p) {
			got = append(got, r.Name)
		}
	}
	slices.Sort(got)
	want := []domain.RoleName{
		domain.RoleAuditor, domain.RoleInvestigator, domain.RoleOrgAdmin, domain.RoleResponder, domain.RoleSecurityAdmin,
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("held by %v, want %v", got, want)
	}
}
