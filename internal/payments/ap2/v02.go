// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ap2

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
)

// currencyRE is an ISO 4217 alphabetic code.
var currencyRE = regexp.MustCompile(`^[A-Z]{3}$`)

// party is an AP2 Merchant (payee or merchant): id and name.
type party struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Website string `json:"website,omitempty"`
}

// amount is an AP2 v0.2 Amount: minor units and an ISO 4217 code.
type amount struct {
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

// v02 verifies an AP2 v0.2 envelope: a checkout mandate and a payment
// mandate bound to it by transaction_id.
func (v *verifier) v02(ctx context.Context, top map[string]jsontext.Value) (Verified, error) {
	for k := range top {
		if k != memberCheckout && k != memberPayment {
			return Verified{}, fmt.Errorf("unknown envelope member %q", k)
		}
	}
	cRaw, pRaw := top[memberCheckout], top[memberPayment]
	if cRaw == nil || pRaw == nil {
		return Verified{}, errors.New("v0.2 needs a checkout mandate and a payment mandate")
	}
	checkout, err := v.mandate(ctx, cRaw, VCTCheckout, VCTCheckoutOpen)
	if err != nil {
		return Verified{}, fmt.Errorf("checkout mandate: %w", err)
	}
	payment, err := v.mandate(ctx, pRaw, VCTPayment, VCTPaymentOpen)
	if err != nil {
		return Verified{}, fmt.Errorf("payment mandate: %w", err)
	}

	// The checkout: the merchant-signed checkout_jwt and its hash.
	cj, _ := checkout.closed["checkout_jwt"].(string)
	ch, _ := checkout.closed["checkout_hash"].(string)
	if cj == "" || ch == "" || ch != hashB64([]byte(cj)) {
		return Verified{}, errors.New("checkout_hash is not the hash of checkout_jwt")
	}
	cpayload, _, err := v.bySignature(ctx, KindMerchant, cj, plainJWTTyp)
	if err != nil {
		return Verified{}, fmt.Errorf("checkout_jwt: %w", err)
	}
	var cclaims map[string]any
	if err := json.Unmarshal(cpayload, &cclaims); err != nil || cclaims == nil {
		return Verified{}, errors.New("checkout_jwt payload")
	}
	if err := v.checkTimes(cclaims); err != nil {
		return Verified{}, fmt.Errorf("checkout_jwt: %w", err)
	}
	merchant := merchantOf(cclaims)
	if merchant == "" {
		return Verified{}, errors.New("checkout_jwt names no merchant (merchant.id or iss)")
	}

	// The payment: bound to the checkout, with payee, amount and an
	// instrument that is never kept.
	txid, _ := payment.closed["transaction_id"].(string)
	if txid != ch {
		return Verified{}, errors.New("transaction_id is not the checkout_jwt hash")
	}
	var payee party
	if err := reclaim(payment.closed["payee"], &payee); err != nil || payee.ID == "" || payee.Name == "" {
		return Verified{}, errors.New("payee")
	}
	var amt amount
	if err := reclaim(payment.closed["payment_amount"], &amt); err != nil || amt.Amount <= 0 || !currencyRE.MatchString(amt.Currency) {
		return Verified{}, errors.New("payment_amount")
	}
	if inst, ok := payment.closed["payment_instrument"].(map[string]any); !ok || inst["id"] == nil || inst["type"] == nil {
		return Verified{}, errors.New("payment_instrument")
	}

	var cons []Constraint
	if checkout.open != nil {
		cs, err := constraintsOf(checkout.open, func(c constraintIn) (Constraint, error) {
			return checkoutConstraint(c, merchant)
		})
		if err != nil {
			return Verified{}, fmt.Errorf("checkout constraints: %w", err)
		}
		cons = append(cons, cs...)
	}
	if payment.open != nil {
		cs, err := constraintsOf(payment.open, func(c constraintIn) (Constraint, error) {
			return paymentConstraint(c, payee, amt)
		})
		if err != nil {
			return Verified{}, fmt.Errorf("payment constraints: %w", err)
		}
		cons = append(cons, cs...)
	}

	canon, err := canonicalJSON(map[string]any{
		"v": V02, memberCheckout: checkout.canonical, memberPayment: payment.canonical,
	})
	if err != nil {
		return Verified{}, err
	}
	return Verified{
		Version: V02, Payee: payee.ID, Merchant: merchant, AmountMinor: amt.Amount, Currency: amt.Currency,
		CheckoutHash: ch, TransactionID: txid, Constraints: cons, ExpiresAt: v.expires,
		MandateDigest: digestOf([]byte(canon)), IssuerAnchorID: payment.issuer,
	}, nil
}

// merchantOf is the checkout's merchant id: merchant.id, else iss.
func merchantOf(claims map[string]any) string {
	if m, ok := claims["merchant"].(map[string]any); ok {
		if id, _ := m["id"].(string); id != "" {
			return id
		}
	}
	iss, _ := claims["iss"].(string)
	return iss
}

// constraintIn is one open mandate constraint as presented.
type constraintIn struct {
	Type     string  `json:"type"`
	Currency string  `json:"currency"`
	Min      *int64  `json:"min"`
	Max      *int64  `json:"max"`
	Allowed  []party `json:"allowed"`
}

// constraintsOf evaluates every constraint of an open mandate with eval;
// an unknown type fails (AP2 v0.2 agent authorization rule 3).
func constraintsOf(open map[string]any, eval func(constraintIn) (Constraint, error)) ([]Constraint, error) {
	raw, present := open["constraints"]
	if !present {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("constraints is not an array")
	}
	out := make([]Constraint, 0, len(list))
	for _, e := range list {
		b, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		var c constraintIn
		if err := json.Unmarshal(b, &c, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("constraint: %w", err)
		}
		got, err := eval(c)
		if err != nil {
			return nil, err
		}
		out = append(out, got)
	}
	return out, nil
}

func partyIDs(ps []party) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.ID != "" {
			out = append(out, p.ID)
		}
	}
	return out
}

func checkoutConstraint(c constraintIn, merchant string) (Constraint, error) {
	switch c.Type {
	case ConstraintAllowedMerchants:
		allowed := partyIDs(c.Allowed)
		if !slices.Contains(allowed, merchant) {
			return Constraint{}, errors.New("merchant is not among the allowed merchants")
		}
		return Constraint{Type: c.Type, Allowed: allowed}, nil
	}
	return Constraint{}, fmt.Errorf("unknown checkout constraint %q", c.Type)
}

func paymentConstraint(c constraintIn, payee party, amt amount) (Constraint, error) {
	switch c.Type {
	case ConstraintAmountRange:
		if c.Max == nil || c.Currency != amt.Currency || amt.Amount > *c.Max || (c.Min != nil && amt.Amount < *c.Min) {
			return Constraint{}, errors.New("amount outside the allowed range")
		}
		out := Constraint{Type: c.Type, Currency: c.Currency, MaxMinor: *c.Max}
		if c.Min != nil {
			out.MinMinor, out.HasMin = *c.Min, true
		}
		return out, nil
	case ConstraintAllowedPayees:
		allowed := partyIDs(c.Allowed)
		if !slices.Contains(allowed, payee.ID) {
			return Constraint{}, errors.New("payee is not among the allowed payees")
		}
		return Constraint{Type: c.Type, Allowed: allowed}, nil
	case ConstraintBudget:
		// The running total over earlier payments is the merchant
		// budget's (D1124); here one payment must fit the budget.
		if c.Max == nil || c.Currency != amt.Currency || amt.Amount > *c.Max {
			return Constraint{}, errors.New("amount over the budget")
		}
		return Constraint{Type: c.Type, Currency: c.Currency, MaxMinor: *c.Max}, nil
	}
	return Constraint{}, fmt.Errorf("unknown payment constraint %q", c.Type)
}
