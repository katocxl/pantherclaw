// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "billing.". The ledger stores each as "audit." + the kind.
const (
	BillingCheckoutRecorded = "billing.checkout_recorded"
	BillingCompGranted = "billing.comp_granted"
	BillingCompRevoked = "billing.comp_revoked"
	BillingPlanApplied = "billing.plan_applied"
	BillingPlanEventIgnored = "billing.plan_event_ignored"
	BillingSubscriptionEnded = "billing.subscription_ended"
)
