// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// TestM14_AuthZENEffectsArePartial: a transaction an AuthZEN enforcement
// point asked about is cooperative, so its effect receipts say PARTIAL
// like the hook's and the SDK's; an a2a one is mediated (G0 M14 D4).
func TestM14_AuthZENEffectsArePartial(t *testing.T) {
	for ch, want := range map[string]bool{"hook": true, "sdk": true, "authzen": true, "http": false, "mcp": false, "a2a": false} {
		if domain.Cooperative(ch) != want {
			t.Errorf("%q: %v", ch, !want)
		}
	}
}
