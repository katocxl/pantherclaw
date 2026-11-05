// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The agent payments reads and writes of the Authority (G0 M39 D1124,
// D1124b; HR-834, HR-840).

var (
	_ pipeline.PaymentReads = (*Reader)(nil)
	_ pipeline.PaymentReads = (*snapshot)(nil)
)

// PaymentCap implements pipeline.PaymentReads.
func (r *Reader) PaymentCap(ctx context.Context, org ids.OrgID, merchant, currency string) (pipeline.PaymentCap, bool, error) {
	type out struct {
		c  pipeline.PaymentCap
		ok bool
	}
	o, err := read(ctx, r, org, func(ctx context.Context, s *snapshot) (out, error) {
		c, ok, err := s.PaymentCap(ctx, org, merchant, currency)
		return out{c, ok}, err
	})
	return o.c, o.ok, err
}

// MandateUse implements pipeline.PaymentReads.
func (r *Reader) MandateUse(ctx context.Context, org ids.OrgID, digest string) (ids.UUID, bool, error) {
	type out struct {
		t  ids.UUID
		ok bool
	}
	o, err := read(ctx, r, org, func(ctx context.Context, s *snapshot) (out, error) {
		t, ok, err := s.MandateUse(ctx, org, digest)
		return out{t, ok}, err
	})
	return o.t, o.ok, err
}

// PaymentCap implements pipeline.PaymentReads: the merchant's ACTIVE cap in
// currency (D1124a).
func (s *snapshot) PaymentCap(ctx context.Context, org ids.OrgID, merchant, currency string) (pipeline.PaymentCap, bool, error) {
	row, err := dbq.New(s.tx).ActivePaymentMerchantCap(ctx, org, merchant, currency)
	if db.IsNoRows(err) {
		return pipeline.PaymentCap{}, false, nil
	}
	if err != nil {
		return pipeline.PaymentCap{}, false, err
	}
	return pipeline.PaymentCap{ID: row.ID, MaxPerPaymentMinor: row.MaxPerPaymentMinor, MaxPerDayMinor: row.MaxPerDayMinor}, true, nil
}

// MandateUse implements pipeline.PaymentReads: the transaction that used
// the mandate digest (D1124b).
func (s *snapshot) MandateUse(ctx context.Context, org ids.OrgID, digest string) (ids.UUID, bool, error) {
	t, err := dbq.New(s.tx).PaymentMandateUse(ctx, org, digest)
	if db.IsNoRows(err) {
		return ids.UUID{}, false, nil
	}
	if err != nil {
		return ids.UUID{}, false, err
	}
	return t, true, nil
}

// useMandate records a permitted payment's single use in the transaction
// that issues its permit (D1124b). A digest another transaction already
// used is ErrConflict: the Authority decides again and refuses it as
// MANDATE_REPLAYED.
func useMandate(ctx context.Context, q *dbq.Queries, org ids.OrgID, w finalize.Write) error {
	p := w.Eval.Payment
	if p == nil || w.Eval.MonitorPermit() {
		return nil
	}
	n, err := q.UsePaymentMandate(ctx, dbq.UsePaymentMandateParams{
		OrgID: org, MandateDigest: p.MandateDigest, TransactionID: w.TransactionID, Merchant: p.Merchant,
		Currency: p.Currency, AmountMinor: p.AmountMinor, Ap2TransactionID: p.TransactionID,
	})
	if err != nil || n == 1 {
		return err
	}
	used, err := q.PaymentMandateUse(ctx, org, p.MandateDigest)
	if err != nil {
		return err
	}
	if used != w.TransactionID {
		return finalize.ErrConflict
	}
	return nil // this transaction's own permit, replaced
}

// paymentEffect records payments.effect for a settled payment (HR-840):
// the mandate digest, merchant, amount, currency, AP2 transaction id and
// outcome, never the mandate. A transaction without a recorded use is not
// a payment.
func paymentEffect(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gatewayID string, txn ids.UUID, o finalize.Outcome) error {
	u, err := q.PaymentMandateUseOfTransaction(ctx, org, txn)
	if db.IsNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	outcome := audit.Success
	if o != finalize.Accepted && o != finalize.Delegated {
		outcome = audit.Failure
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: auditkind.PaymentsEffect, Actor: evdomain.Actor{Type: "gateway", ID: gatewayID}, Outcome: outcome,
		Object: &audit.Object{Type: "transaction", ID: txn.String()},
		Details: map[string]string{
			"mandate_digest": u.MandateDigest, "merchant": u.Merchant, "currency": u.Currency,
			"amount_minor": strconv.FormatInt(u.AmountMinor, 10), "transaction_id": u.Ap2TransactionID, "outcome": string(o),
		},
	})
	return err
}
