// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M30 owned account permissions (G0 M30 D933, HR-708).
//
//   - org.owned_accounts.read: see the org's owned accounts. Org Admin,
//     Security Admin and Auditor hold it.
//   - org.owned_accounts.manage: add an account (a protected change) or
//     remove one. Only Security Admin holds it, and only a person can
//     exercise it.
const (
	PermOwnedAccountsRead   Permission = "org.owned_accounts.read"
	PermOwnedAccountsManage Permission = "org.owned_accounts.manage"
)

// m30Catalog are the M30 permissions in catalog order.
var m30Catalog = []Permission{PermOwnedAccountsRead, PermOwnedAccountsManage}

// m30HumanOnly are the ones only a person may hold.
var m30HumanOnly = []Permission{PermOwnedAccountsManage}
