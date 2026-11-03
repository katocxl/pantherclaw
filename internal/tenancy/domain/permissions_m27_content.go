// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M27 content signal permissions (G0 M27 D507, HR-647).
//
//   - content.read: see the org's content signal mode and what WATCHING would
//     have held. Org Admin, Security Admin and Auditor hold it.
//   - content.manage: change the mode. Only Security Admin holds it, and only
//     a person can exercise it.
const (
	PermContentRead   Permission = "content.read"
	PermContentManage Permission = "content.manage"
)

// m27ContentCatalog are the M27 content permissions in catalog order.
var m27ContentCatalog = []Permission{PermContentRead, PermContentManage}

// m27ContentHumanOnly are the ones only a person may hold.
var m27ContentHumanOnly = []Permission{PermContentManage}
