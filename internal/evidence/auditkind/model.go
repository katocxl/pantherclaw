// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "model.". The ledger stores each as "audit." + the kind.
const (
	ModelCall             = "model.call"
	ModelCallStarted      = "model.call.started"
	ModelDraftingDisabled = "model.drafting_disabled"
	ModelDraftingEnabled  = "model.drafting_enabled"
	ModelKeyCleared       = "model.key_cleared"
	ModelKeySet           = "model.key_set"
	ModelSettingsUpdated  = "model.settings_updated"
)
