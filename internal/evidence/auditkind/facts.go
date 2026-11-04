// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "facts.". The ledger stores each as "audit." + the kind.
const (
	FactsProviderDisabled   = "facts.provider_disabled"
	FactsProviderRegistered = "facts.provider_registered"
)
