// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M39 agent payment permissions (G0 M39 D1121; HR-830..832, HR-838):
//
//   - payments.read: see the org's payment trust anchors and check agent
//     request signatures for a merchant backend. Org Admin, Security Admin
//     and Auditor hold it.
//   - payments.manage: create, activate (with a security key, on the page)
//     and revoke trust anchors. Security Admin holds it, and only a person
//     can exercise it.
const (
	PermPaymentsRead   Permission = "payments.read"
	PermPaymentsManage Permission = "payments.manage"
)

// m39Catalog are the M39 payment permissions in catalog order.
var m39Catalog = []Permission{PermPaymentsRead, PermPaymentsManage}

func init() {
	catalog = append(catalog, m39Catalog...)
	humanOnly = append(humanOnly, PermPaymentsManage)
	for i := range roles {
		r := &roles[i]
		switch r.Name { //nolint:exhaustive // only these roles gain the M39 payment permissions
		case RoleSecurityAdmin:
			r.Permissions = append(r.Permissions, PermPaymentsRead, PermPaymentsManage)
			r.Description += " Manages the sandbox trust anchors of agent payments (activated with a security key)."
		case RoleOrgAdmin, RoleAuditor:
			r.Permissions = append(r.Permissions, PermPaymentsRead)
			r.Description += " Reads the org's agent payment trust anchors and checks agent request signatures."
		}
	}
}
