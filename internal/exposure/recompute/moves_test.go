// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recompute

import (
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
)

// TestHR664_MovingNamesKnownKinds: every exact kind that moves reach is an
// audit kind the core writes, and every audit prefix starts one, so a
// stale or misspelled entry can't let a reach change go unrecomputed
// (HR-664).
func TestHR664_MovingNamesKnownKinds(t *testing.T) {
	t.Parallel()
	var ledger []string
	for _, k := range auditkind.All() {
		ledger = append(ledger, "audit."+k)
	}
	for _, k := range movingKinds {
		if !slices.Contains(ledger, k) {
			t.Errorf("moving kind %q is no audit kind the core writes", k)
		}
	}
	for _, p := range moving {
		if !strings.HasPrefix(p, "audit.") {
			continue // a feed kind, not an audit entry
		}
		if slices.Contains(ledger, p) {
			t.Errorf("moving prefix %q is a whole kind; list it in movingKinds", p)
		}
		if !slices.ContainsFunc(ledger, func(k string) bool { return strings.HasPrefix(k, p+".") || strings.HasPrefix(k, p+"_") }) {
			t.Errorf("moving prefix %q starts no audit kind the core writes", p)
		}
	}
	for kind, want := range map[string]bool{
		"audit.policy.published": true, "audit.guardrails.changed": true, "audit.policy.published_x": false,
		"audit.policy.exception_revoked": true, "audit.policy.version_created": false,
	} {
		if Moves(kind) != want {
			t.Errorf("Moves(%q) = %v, want %v", kind, !want, want)
		}
	}
}
