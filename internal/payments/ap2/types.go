// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ap2 verifies Agent Payments Protocol mandates (G0 M39 D1122;
// FQ39-1; HR-830, HR-833). PantherClaw verifies mandates and never signs
// them, and it keeps no payment credential: a payment instrument is only
// ever seen as a digest.
//
// Two protocol versions are accepted, in a JSON envelope (Verify):
//
//   - AP2 v0.2: SD-JWT checkout mandates (vct mandate.checkout.1, with the
//     merchant-signed checkout_jwt and checkout_hash) and payment mandates
//     (vct mandate.payment.1), each optionally delegated through an open
//     mandate (vct mandate.checkout.open.1 or mandate.payment.open.1) whose
//     cnf key signs the closed one. Open mandate constraints are evaluated
//     and unknown constraints fail; values the open mandate sets must be
//     unchanged in the closed one.
//   - AP2 v0.1: a CartMandate whose merchant_authorization JWT carries
//     cart_hash (SHA-256 of the RFC 8785 form of CartContents) and a
//     PaymentMandate whose user_authorization SD-JWT-VC ends in a KB-JWT
//     whose transaction_data holds the cart and payment hashes. An
//     IntentMandate is informational and never proof.
//
// Every mandate issuer must be an ACTIVE MANDATE_ISSUER trust anchor and
// every checkout or cart signer an ACTIVE MERCHANT anchor; anchors are
// sandbox only (D1120, HR-831).
package ap2

import (
	"context"
	"crypto"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Versions.
const (
	V01 = "0.1"
	V02 = "0.2"
)

// Kind is a trust anchor's kind (D1121).
type Kind string

// Trust anchor kinds.
const (
	KindMandateIssuer  Kind = "MANDATE_ISSUER"
	KindMerchant       Kind = "MERCHANT"
	KindAgentDirectory Kind = "AGENT_DIRECTORY"
)

// AnchorKey is one verification key of an ACTIVE trust anchor.
type AnchorKey struct {
	AnchorID ids.UUID
	Key      crypto.PublicKey
}

// Anchors resolves the org's ACTIVE sandbox trust anchors' keys
// (anchors.Service.ForOrg).
type Anchors interface {
	// Keys returns the keys named kid of the ACTIVE anchors of kind; none
	// is not an error. A live (non-sandbox) anchor fails with
	// ErrLiveRefused.
	Keys(ctx context.Context, kind Kind, kid string) ([]AnchorKey, error)
	// Audiences are the aud values a KB-JWT or a delegated closed mandate
	// must name (D1122b); empty makes Verify refuse every mandate.
	Audiences() []string
}

// WithAudiences returns a with the expected audiences aud (D1122b): the
// caller pins the audience, such as the agentpay connection's merchant
// audience; empty values are dropped.
func WithAudiences(a Anchors, aud ...string) Anchors {
	if a == nil {
		return nil
	}
	var keep []string
	for _, s := range aud {
		if s != "" {
			keep = append(keep, s)
		}
	}
	return audienced{Anchors: a, aud: keep}
}

type audienced struct {
	Anchors
	aud []string
}

func (a audienced) Audiences() []string { return a.aud }

// Constraint types evaluated (D1122). Any other type fails.
const (
	ConstraintAmountRange      = "payment.amount_range"
	ConstraintAllowedPayees    = "payment.allowed_payees"
	ConstraintBudget           = "payment.budget"
	ConstraintAllowedMerchants = "checkout.allowed_merchants"
)

// Constraint is an open mandate constraint that the closed mandate met.
type Constraint struct {
	// Type is one of the Constraint* types.
	Type string
	// Currency, MinMinor and MaxMinor are an amount range or budget, in
	// minor units; HasMin says whether a range has a lower bound.
	Currency string
	MinMinor int64
	HasMin   bool
	MaxMinor int64
	// Allowed are the payee or merchant ids allowed.
	Allowed []string
}

// Verified is a verified mandate chain (D1122). It carries no payment
// credential.
type Verified struct {
	// Version is V01 or V02.
	Version string
	// Payee is the payment mandate's payee id (v0.2 payee.id, v0.1
	// merchant_agent).
	Payee string
	// Merchant is the checkout or cart signer's merchant id (v0.2
	// checkout_jwt merchant.id or iss, v0.1 merchant_authorization iss).
	Merchant string
	// AmountMinor and Currency are the payment amount in ISO 4217 minor
	// units.
	AmountMinor int64
	Currency    string
	// CartHash is the v0.1 cart_hash; CheckoutHash the v0.2 checkout_hash.
	CartHash     string
	CheckoutHash string
	// TransactionID is the v0.2 transaction_id (the checkout_jwt hash) or
	// the v0.1 payment_mandate_id.
	TransactionID string
	// Constraints are the open mandates' constraints, all met.
	Constraints []Constraint
	// ExpiresAt is the earliest expiry in the chain.
	ExpiresAt time.Time
	// MandateDigest identifies the verified chain: "sha256:" and the hex
	// SHA-256 of its canonical form (canonical.go).
	MandateDigest string
	// IssuerAnchorID is the payment mandate issuer's trust anchor.
	IssuerAnchorID ids.UUID
}

// Errors.
var (
	// ErrInvalid is any mandate that does not verify, is expired or whose
	// constraints fail (MANDATE_INVALID); the wrapped detail is for logs.
	ErrInvalid = pcerr.New(pcerr.Deny, "MANDATE_INVALID", "the payment mandate did not verify")
	// ErrLiveRefused is a mandate or anchor outside the sandbox (D1120).
	ErrLiveRefused = pcerr.New(pcerr.Deny, "PAYMENTS_LIVE_REFUSED",
		"agent payments run in sandbox only: a live anchor, key or host is refused")
)
