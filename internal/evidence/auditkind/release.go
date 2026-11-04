// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "release.". The ledger stores each as "audit." + the kind.
const (
	ReleaseWindowCreated = "release.window.created"
	ReleaseWindowRetired = "release.window.retired"
)
