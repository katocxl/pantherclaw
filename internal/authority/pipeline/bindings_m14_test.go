// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
)

// refundAtMost binds a refund's amount to at most the charge's remaining
// refundable amount (G0 M14 D48: pc.stripe's refund ≤ the fact's
// remaining amount).
func refundAtMost(raw []byte) []byte {
	return bytes.Replace(raw, []byte("      - fact: payments.charge.refundable\n        max_age_seconds: 300\n"),
		[]byte("      - fact: payments.charge.refundable\n        max_age_seconds: 300\n      - fact: payments.charge.state\n"+
			"        max_age_seconds: 300\n        binds: {member: remaining, param: amount, reason: AMOUNT_NOT_REFUNDABLE, op: le}\n"), 1)
}

// TestM14_AnAmountBoundAtMostItsFact: with an le binding, a refund up to
// the fact's remaining amount is decided as before; more is
// CANNOT_AUTHORIZE with the binding's reason; another currency is
// CANNOT_AUTHORIZE CURRENCY_MISMATCH; a missing or malformed member fails
// closed (G0 M14 D48).
func TestM14_AnAmountBoundAtMostItsFact(t *testing.T) {
	f := newFxWith(t, refundAtMost, "")
	f.state("ch_1", map[string]any{"remaining": map[string]any{"value": "40.00", "currency": "USD"}})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Allow, pipeline.ReasonGrantCovers)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "40.00")), adomain.Allow, pipeline.ReasonGrantCovers)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "40.01")), adomain.CannotAuthorize, "AMOUNT_NOT_REFUNDABLE")

	f.state("ch_1", map[string]any{"remaining": map[string]any{"value": "40.00", "currency": "EUR"}})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, pipeline.ReasonCurrencyMismatch)

	for _, member := range []map[string]any{
		{"other": "x"},
		{"remaining": "40.00"},
		{"remaining": map[string]any{"value": "40", "currency": "USD"}},
		{"remaining": map[string]any{"value": "40.00", "currency": "USD", "extra": true}},
	} {
		f.state("ch_1", member)
		expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, "AMOUNT_NOT_REFUNDABLE")
	}
}
