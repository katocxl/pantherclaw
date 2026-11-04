// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "saas.". The ledger stores each as "audit." + the kind.
const (
	SaasScanFinished = "saas.scan_finished"
	SaasScanStarted  = "saas.scan_started"
)
