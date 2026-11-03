// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR660_VerifyAcceptsTheCredentialClaim: an execution receipt that
// names the credential version the gateway opened verifies like one that
// names none; the verifier ignores claims it does not check (PAP-1 §9.2).
// Covers: F952
func TestHR660_VerifyAcceptsTheCredentialClaim(t *testing.T) {
	iss := bundletest.NewIssuer(t)
	iss.Append(1)
	iss.AppendExecution(ids.NewV7().String(), map[string]any{
		"outcome": "accepted", "recorded_by": "gateway",
		"credential": map[string]any{"id": ids.NewV7().String(), "version": 2},
	})
	iss.AppendExecution(ids.NewV7().String(), map[string]any{"outcome": "accepted", "recorded_by": "gateway"})
	iss.Checkpoint()
	r := verifyClosure(t, iss, iss.Bundle())
	if r.Failed() {
		t.Fatalf("a receipt with the credential claim failed:\n%s", r.Text())
	}
	for _, name := range []string{"receipt.signature", "receipt.ledger"} {
		checks := checksNamed(r, name)
		if len(checks) != 3 {
			t.Fatalf("%d %s checks, want 3:\n%s", len(checks), name, r.Text())
		}
		for _, c := range checks {
			if c.Status != bundle.Passed {
				t.Fatalf("%s %s: %s %s", name, c.Subject, c.Status, c.Detail)
			}
		}
	}
}
