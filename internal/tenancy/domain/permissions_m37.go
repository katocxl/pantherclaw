// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M37 publisher and bundle permissions (G0 M37 D1081; FQ37-1):
//
//   - publisher.manage: pin a publisher's key, activate the pin (with a
//     security key, on its page) and revoke it. Org Admin and Security
//     Admin hold it, and only a person can exercise it.
//   - bundle.install: install a publisher bundle (drafts only), revoke an
//     install and submit a publisher's revocation statement. Org Admin and
//     Security Admin hold it.
//   - bundle.read: see pins, installs and their items. Org Admin, Security
//     Admin and Auditor hold it.
const (
	PermPublisherManage Permission = "publisher.manage"
	PermBundleInstall   Permission = "bundle.install"
	PermBundleRead      Permission = "bundle.read"
)

// m37Catalog are the M37 permissions in catalog order.
var m37Catalog = []Permission{PermPublisherManage, PermBundleInstall, PermBundleRead}

func init() {
	catalog = append(catalog, m37Catalog...)
	humanOnly = append(humanOnly, PermPublisherManage)
	for i := range roles {
		r := &roles[i]
		switch r.Name { //nolint:exhaustive // only these roles gain the M37 permissions
		case RoleOrgAdmin, RoleSecurityAdmin:
			r.Permissions = append(r.Permissions, PermPublisherManage, PermBundleInstall, PermBundleRead)
			r.Description += " Pins publisher keys (activated with a security key) and installs their bundles as drafts."
		case RoleAuditor:
			r.Permissions = append(r.Permissions, PermBundleRead)
			r.Description += " Reads the org's publisher pins and bundle installs."
		}
	}
}
