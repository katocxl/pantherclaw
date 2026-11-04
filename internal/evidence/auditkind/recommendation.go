// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "recommendation.". The ledger stores each as "audit." + the kind.
const (
	RecommendationDismissed = "recommendation.dismissed"
	RecommendationUndismissed = "recommendation.undismissed"
)
