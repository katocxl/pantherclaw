// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR655_InvestigatorHoldsReadsOnly: the role holds these reads, exactly;
// each is a .read permission, none is restricted evidence, and it binds only
// to service accounts.
// Covers: F946
func TestHR655_InvestigatorHoldsReadsOnly(t *testing.T) {
	r, ok := domain.LookupRole(domain.RoleInvestigator)
	if !ok {
		t.Fatal("no Investigator role")
	}
	want := []domain.Permission{
		domain.PermOrgRead, domain.PermSearchRead, domain.PermEvidenceRead, domain.PermExposureRead,
		domain.PermAgentRead, domain.PermRunRead, domain.PermGrantRead, domain.PermIncidentRead,
	}
	if !slices.Equal(r.Permissions, want) {
		t.Errorf("Investigator holds %v", r.Permissions)
	}
	for _, p := range r.Permissions {
		if !strings.HasSuffix(string(p), ".read") {
			t.Errorf("%s is not a read", p)
		}
	}
	if r.Has(domain.PermEvidenceReadRestricted) {
		t.Error("Investigator reads restricted evidence")
	}
	if r.HumanOnly() {
		t.Error("a human-only permission would keep the role off service accounts")
	}
	if !r.ServiceOnly {
		t.Error("Investigator can be bound to a person")
	}
	if _, err := domain.CheckBindable(domain.RoleInvestigator, domain.KindServiceAccount, domain.ScopeTeam); err != nil {
		t.Errorf("Investigator on a service account: %v", err)
	}
	if _, err := domain.CheckBindable(domain.RoleInvestigator, domain.KindUser, domain.ScopeTeam); err == nil {
		t.Error("Investigator bound to a user")
	}
}
