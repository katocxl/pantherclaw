// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
)

// D34 (f): a range pack whose receipts are not in the pack still verifies
// what it holds, says it is not fully verifiable, and exposes that so a
// baseline gate can refuse it.
func TestD34_ARangePackWithoutItsReceiptsIsNotFullyVerifiable(t *testing.T) {
	k := newPackKit(t)
	full := verifyRangePack(k, goodRange())
	if full.RangeNotFullyVerifiable() {
		t.Fatalf("a complete range pack is not fully verifiable:\n%s", full.Text())
	}
	// The transaction file carries no receipt body (removed by retention).
	o := goodRange()
	o.noReceipts = true
	r := verifyRangePack(k, o)
	if !r.RangeNotFullyVerifiable() || statusOf(r, "range.complete") != bundle.NotAvailable {
		t.Fatalf("a pack without receipts:\n%s", r.Text())
	}
	if r.Failed() {
		t.Fatalf("missing receipts must not fail the pack:\n%s", r.Text())
	}
}

// D34 (a): the step may name any reason of the decision receipt, not only
// the decisive one.
func TestD34_AStepMayNameAnyReasonOfTheReceipt(t *testing.T) {
	k := newPackKit(t)
	o := goodRange()
	o.stepReason = "SECOND"
	o.extraReasons = true
	if got := statusOf(verifyRangePack(k, o), "range.step"); got != bundle.Passed {
		t.Fatalf("the second reason = %q, want passed", got)
	}
	o.stepReason = "NOT_A_REASON"
	if got := statusOf(verifyRangePack(k, o), "range.step"); got != bundle.Failed {
		t.Fatalf("a reason the receipt lacks = %q, want failed", got)
	}
}

// D34 (d): a PASS over fewer steps than the scenario declares fails.
func TestD34_APassOverFewerStepsThanDeclaredFails(t *testing.T) {
	k := newPackKit(t)
	o := goodRange()
	o.stepCount = 2
	if got := statusOf(verifyRangePack(k, o), "range.verdict"); got != bundle.Failed {
		t.Fatalf("PASS with 1 of 2 steps = %q, want failed", got)
	}
}
