// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M35 federation permissions (G0 M35 D1021).
//
//   - federation.read: see the org's federation document, keys, trusts,
//     listings, peer agents and receipts. Org Admin, Security Admin and
//     Auditor hold it.
//   - federation.manage: set the endpoint, rotate the key, propose,
//     confirm, refresh and revoke trusts, and create and retire listings.
//     Org Admin and Security Admin hold it, and only a person can exercise
//     it.
const (
	PermFederationRead   Permission = "federation.read"
	PermFederationManage Permission = "federation.manage"
)

// m35Catalog are the M35 permissions in catalog order.
var m35Catalog = []Permission{PermFederationRead, PermFederationManage}

func init() {
	catalog = append(catalog, m35Catalog...)
	humanOnly = append(humanOnly, PermFederationManage)
	for i := range roles {
		r := &roles[i]
		switch r.Name { //nolint:exhaustive // only these roles gain the M35 federation permissions
		case RoleOrgAdmin, RoleSecurityAdmin:
			r.Permissions = append(r.Permissions, PermFederationRead, PermFederationManage)
			r.Description += " Manages cross-org federation: trusts with peer orgs (with a security key) and listed agents."
		case RoleAuditor:
			r.Permissions = append(r.Permissions, PermFederationRead)
			r.Description += " Reads cross-org federation trusts, listings and receipts."
		}
	}
}
