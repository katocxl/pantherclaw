// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
)

// TestReflexEditions: G0 M10 D5. Team gets grouping, suppression,
// notifications, cases and breach radius; Business adds the advanced and
// custom detections, posture remediation, SIEM export, SOAR and Shared
// Signals. Community gets none of the helpers.
func TestReflexEditions(t *testing.T) {
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
		for name, got := range map[string]bool{"ReflexTeam": e.ReflexTeam(), "Cases": e.Cases(), "BreachRadius": e.BreachRadius()} {
			if got != tc.team {
				t.Errorf("%s %s = %v, want %v", tc.ed, name, got, tc.team)
			}
		}
		for name, got := range map[string]bool{
			"AdvancedDetections": e.AdvancedDetections(), "CustomDetections": e.CustomDetections(),
			"PostureRemediation": e.PostureRemediation(), "SIEMExport": e.SIEMExport(), "SOAR": e.SOAR(),
			"SharedSignals": e.SharedSignals(),
		} {
			if got != tc.business {
				t.Errorf("%s %s = %v, want %v", tc.ed, name, got, tc.business)
			}
		}
	}
}
