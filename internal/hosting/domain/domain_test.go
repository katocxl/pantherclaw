// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
)

// TestT218_ThePlanQuotaBoundsEveryHostedGateway: Community gets no hosted
// gateway, Team the default profile at most, larger editions up to the
// ceilings; unset limits take the defaults.
//
// Covers: PN-010.4
func TestT218_ThePlanQuotaBoundsEveryHostedGateway(t *testing.T) {
	if _, err := Fit(billing.Entitlements{Edition: billing.Community}, profile.Limits{}); !errors.Is(err, ErrEdition) {
		t.Fatalf("community: %v", err)
	}
	team := billing.Entitlements{Edition: billing.Team}
	if l, err := Fit(team, profile.Limits{}); err != nil || l != profile.DefaultLimits {
		t.Fatalf("team default: %+v %v", l, err)
	}
	if _, err := Fit(team, profile.Limits{MemoryMiB: profile.DefaultLimits.MemoryMiB + 1}); !errors.Is(err, ErrQuota) {
		t.Fatalf("team over quota: %v", err)
	}
	if _, err := Fit(team, profile.Limits{PIDs: 1}); !errors.Is(err, ErrQuota) {
		t.Fatalf("below the floor: %v", err)
	}
	ent := billing.Entitlements{Edition: billing.Enterprise}
	if l, err := Fit(ent, profile.Ceilings); err != nil || l != profile.Ceilings {
		t.Fatalf("enterprise ceilings: %+v %v", l, err)
	}
	if _, err := Fit(ent, profile.Limits{MilliCPUs: profile.Ceilings.MilliCPUs + 1}); !errors.Is(err, ErrQuota) {
		t.Fatalf("over the ceiling: %v", err)
	}
	for s, ok := range map[string]bool{"acme": true, "a-b": true, "-a": false, "A": false, "a_b": false, "": false} {
		if ValidSlug(s) != ok {
			t.Errorf("ValidSlug(%q) != %v", s, ok)
		}
	}
}
