// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "identity_provider.". The ledger stores each as "audit." + the kind.
const (
	IdentityProviderActivated  = "identity_provider.activated"
	IdentityProviderCreated    = "identity_provider.created"
	IdentityProviderDisabled   = "identity_provider.disabled"
	IdentityProviderLapsed     = "identity_provider.lapsed"
	IdentityProviderOwnOnlySet = "identity_provider.own_only_set"
)
