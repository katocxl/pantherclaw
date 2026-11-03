// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM25_ComplianceReadRoles: compliance.read and the roles that hold it,
// exactly (G0 M25 D311).
// Covers: F892
func TestM25_ComplianceReadRoles(t *testing.T) {
	p := domain.PermComplianceRead
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
	want := []domain.RoleName{domain.RoleAuditor, domain.RoleOrgAdmin, domain.RoleSecurityAdmin}
	if !slices.Equal(got, want) {
		t.Fatalf("held by %v", got)
	}
}
