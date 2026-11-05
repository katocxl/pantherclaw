// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording

import (
	"context"
	"errors"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The payment step's reads (G0 M39 D1124) pass through the Recorder
// unrecorded: a recording does not hold the mandate's verification, so a
// replay of a payment is CANNOT_AUTHORIZE whatever these reads were
// (pipeline Version 11). The replay Reader does not implement the port.

var _ pipeline.PaymentReads = (*Recorder)(nil)

var errNoPaymentReads = errors.New("recording: the wrapped reader has no payment reads")

// PaymentCap implements pipeline.PaymentReads.
func (r *Recorder) PaymentCap(ctx context.Context, org ids.OrgID, merchant, currency string) (pipeline.PaymentCap, bool, error) {
	if port, ok := r.r.(pipeline.PaymentReads); ok {
		return port.PaymentCap(ctx, org, merchant, currency)
	}
	return pipeline.PaymentCap{}, false, errNoPaymentReads
}

// MandateUse implements pipeline.PaymentReads.
func (r *Recorder) MandateUse(ctx context.Context, org ids.OrgID, digest string) (ids.UUID, bool, error) {
	if port, ok := r.r.(pipeline.PaymentReads); ok {
		return port.MandateUse(ctx, org, digest)
	}
	return ids.UUID{}, false, errNoPaymentReads
}
