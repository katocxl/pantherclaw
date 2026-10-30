// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestAMissingCustomerRuleIsNamedInTheGap (G0 M17 D144): a replay that
// could not load a recorded customer rule version as it was does not
// decide without it, and its gap names the version.
//
// Covers: F405
func TestAMissingCustomerRuleIsNamedInTheGap(t *testing.T) {
	org := ids.New[ids.Org]()
	rec := &recording.Recording{}
	rec.Reads.CustomerRules = &recording.CustomerRules{Rules: []recording.CustomerRule{
		{ID: "cx.first", Version: 1, Digest: strings.Repeat("00", 32)},
		{ID: "cx.second", Version: 3, Digest: strings.Repeat("11", 32)},
	}}
	r := recording.NewReader(org, rec, recording.Served{MissingCustomerRules: []string{"cx.first v1", "cx.second v3"}})
	if rules, err := r.CustomerRules(t.Context(), org); err == nil || rules != nil {
		t.Fatalf("decided without the recorded rules: %v %v", rules, err)
	}
	gaps := r.Gaps()
	if len(gaps) != 1 || gaps[0].Read != "customer_rules" || !strings.Contains(gaps[0].Detail, "cx.first v1, cx.second v3") {
		t.Fatalf("gaps %+v", gaps)
	}
}
