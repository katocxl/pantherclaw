// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of approval reach (G0 M36 D1063..D1066): fatigue flags and
// routing, deputies, notification preferences and Web Push subscriptions.
// None of them records an approval: nothing these features do approves
// anything (HR-789).
const (
	ApprovalDeputyCancelled   = "approval.deputy_cancelled" //nolint:misspell // the published audit kind
	ApprovalDeputyNotEligible = "approval.deputy_not_eligible"
	ApprovalDeputySet         = "approval.deputy_set"
	ApprovalFatigueFlagged    = "approval.fatigue_flagged"
	ApprovalFatigueRoutingSet = "approval.fatigue_routing_set"

	NotificationPreferencesSet             = "notification.preferences_set"
	NotificationPushSubscriptionRegistered = "notification.push_subscription_registered"
	NotificationPushSubscriptionRemoved    = "notification.push_subscription_removed"
)
