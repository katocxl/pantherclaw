// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "suggestion.". The ledger stores each as "audit." + the kind.
const (
	SuggestionDismissed = "suggestion.dismissed"
	SuggestionDrafted = "suggestion.drafted"
)
