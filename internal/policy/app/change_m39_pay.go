// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

// ChangePaymentCap activates a merchant cap for agent payments (G0 M39
// D1124, D1124a; HR-836): creating or raising a cap is a loosening, so it
// goes through a change request confirmed with security keys. Its apply
// callback (internal/payments/caps) voids a request that needs fewer than
// two confirmations (VoidTwoPeopleRequired), so a cap is never activated by
// one person alone.
const ChangePaymentCap ChangeKind = "PAYMENT_CAP"

// VoidTwoPeopleRequired voids a PAYMENT_CAP request the org's single
// publisher could confirm alone (D1124a Q3).
const VoidTwoPeopleRequired = "TWO_PEOPLE_REQUIRED"
