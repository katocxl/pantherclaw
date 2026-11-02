// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/campaigns/adapters/pgcampaigns"
)

// TestCampaignResultsReadTheCampaignTables: the read port compliance
// evidence takes (G0 M25 D312) is the campaign store, the one module that
// knows the tables.
// Covers: F900
func TestCampaignResultsReadTheCampaignTables(t *testing.T) {
	if _, ok := campaignResults(nil).(pgcampaigns.Store); !ok {
		t.Fatal("campaignResults is not the campaign store")
	}
}
