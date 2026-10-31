// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M23 permissions (G0 M23 D103, Community).
//
//   - hub.read: see what the org installed from PantherClaw Hub and the last
//     Hub index it accepted.
//   - hub.install: install a Hub item as an inert draft (HR-561). It is for
//     people only, but Org Admin stays bindable to service accounts, so like
//     identity_provider.manage it is not in humanOnly: the Hub service
//     refuses any caller but a person. Holding it creates nothing alone:
//     each kind of item goes through its own use case, which checks its own
//     permission (policy.author, detection.manage, automation.manage or
//     package.import).
const (
	PermHubRead    Permission = "hub.read"
	PermHubInstall Permission = "hub.install"
)

// m23Catalog are the M23 permissions in catalog order.
var m23Catalog = []Permission{PermHubRead, PermHubInstall}
