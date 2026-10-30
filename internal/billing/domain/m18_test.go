// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
)

// TestM18Editions: G0 M18 D159. Team gets API-key IP allow lists and the
// fleet view; Enterprise adds the fleet policy and alerts, delegated
// administration, large-fleet administration and organization identity
// providers. Community gets none of them.
//
// Covers: PN-012.8, PN-010.6, F584, F602, PN-012.7
func TestM18Editions(t *testing.T) {
	for _, tc := range []struct {
		ed               domain.Edition
		team, enterprise bool
	}{
		{domain.Community, false, false},
		{domain.Team, true, false},
		{domain.Business, true, false},
		{domain.Enterprise, true, true},
	} {
		e := domain.Entitlements{Edition: tc.ed}
		for name, got := range map[string]bool{"APIKeyIPAllowLists": e.APIKeyIPAllowLists(), "FleetView": e.FleetView()} {
			if got != tc.team {
				t.Errorf("%s %s = %v, want %v", tc.ed, name, got, tc.team)
			}
		}
		for name, got := range map[string]bool{
			"FleetPolicy": e.FleetPolicy(), "DelegatedAdmin": e.DelegatedAdmin(),
			"LargeFleetAdmin": e.LargeFleetAdmin(), "OrgIdentityProviders": e.OrgIdentityProviders(),
		} {
			if got != tc.enterprise {
				t.Errorf("%s %s = %v, want %v", tc.ed, name, got, tc.enterprise)
			}
		}
	}
}
