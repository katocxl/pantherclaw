// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import "testing"

// TestHR231_TheServerReadsDigestsInTheConfirmingTx (G0 M11.1 D29): the
// server's change requests read the current definitions and catalog
// digests in the transaction that applies a change, never through the
// test-only fallback, and the gate has both of its ports.
func TestHR231_TheServerReadsDigestsInTheConfirmingTx(t *testing.T) {
	v := newPolicyVersions(nil, nil, "https://pc.example.test")
	if v.Changes == nil || !v.Changes.DigestsInTx() {
		t.Fatal("the server's change requests read the digests outside the confirming transaction")
	}
	if v.Validator == nil || v.Tests == nil {
		t.Fatal("the server's gate lacks a validator or a test runner")
	}
}
