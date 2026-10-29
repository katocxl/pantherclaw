// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package live_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/adapters/live"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// TestCustomerStepKindsAreTheLiveKinds: a customer scenario uses exactly the
// step kinds the live driver runs, and no harness kind (G0 M17 D126).
// Covers: PN-009.6
func TestCustomerStepKindsAreTheLiveKinds(t *testing.T) {
	d := live.New(live.Config{})
	for _, k := range domain.StepKinds {
		allowed := false
		for _, c := range domain.CustomerStepKinds {
			allowed = allowed || c == k
		}
		if allowed != d.Supports(k) {
			t.Errorf("%s: customer kind %v, live driver supports %v", k, allowed, d.Supports(k))
		}
	}
}
