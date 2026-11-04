// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "protected_change.". The ledger stores each as "audit." + the kind.
const (
	ProtectedChangeApplied           = "protected_change.applied"
	ProtectedChangeCategoryEnabled   = "protected_change.category_enabled"
	ProtectedChangeEmergencyApplied  = "protected_change.emergency_applied"
	ProtectedChangeEmergencyReviewed = "protected_change.emergency_reviewed"
	ProtectedChangeRequested         = "protected_change.requested"
	ProtectedChangeReviewExpired     = "protected_change.review_expired"
	ProtectedChangeReviewReopened    = "protected_change.review_reopened"
)
