// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "signing_key.". The ledger stores each as "audit." + the kind.
const (
	SigningKeyCreated = "signing_key.created"
	SigningKeyRetiring = "signing_key.retiring"
	SigningKeyRevoked = "signing_key.revoked"
	SigningKeyRewrapped = "signing_key.rewrapped"
)
