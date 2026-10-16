// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
)

// TestAutomationEditions: G0 M11 part 2 D12. Team gets automations,
// cohorts and reference packs; Business adds playbook containment, latent
// exposure and compromised publishers. Community gets none of them.
func TestAutomationEditions(t *testing.T) {
	for _, tc := range []struct {
		ed             domain.Edition
		team, business bool
	}{
		{domain.Community, false, false},
		{domain.Team, true, false},
		{domain.Business, true, true},
		{domain.Enterprise, true, true},
	} {
		e := domain.Entitlements{Edition: tc.ed}
		for name, got := range map[string]bool{"Automations": e.Automations(), "Cohorts": e.Cohorts(), "ReferencePacks": e.ReferencePacks()} {
			if got != tc.team {
				t.Errorf("%s %s = %v, want %v", tc.ed, name, got, tc.team)
			}
		}
		for name, got := range map[string]bool{
			"AutomationPlaybooks": e.AutomationPlaybooks(), "AutomationLatentExposure": e.AutomationLatentExposure(),
			"PublisherCompromise": e.PublisherCompromise(),
		} {
			if got != tc.business {
				t.Errorf("%s %s = %v, want %v", tc.ed, name, got, tc.business)
			}
		}
	}
}
