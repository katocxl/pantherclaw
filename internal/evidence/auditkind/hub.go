// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "hub.". The ledger stores each as "audit." + the kind.
const (
	HubItemInstallFailed = "hub.item_install_failed"
	HubItemInstalled     = "hub.item_installed"
)
