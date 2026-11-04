// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "saml.". The ledger stores each as "audit." + the kind.
const (
	SamlConnectionDisabled = "saml.connection_disabled"
	SamlConnectionPut      = "saml.connection_put"
)
