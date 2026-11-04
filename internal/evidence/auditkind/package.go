// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "package.". The ledger stores each as "audit." + the kind.
const (
	PackageImported             = "package.imported"
	PackageSigningKeyRegistered = "package.signing_key.registered"
	PackageSigningKeyRevoked    = "package.signing_key.revoked"
	PackageTransitioned         = "package.transitioned"
)
