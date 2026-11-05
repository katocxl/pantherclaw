// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M38 threat-intel permissions (G0 M38 D1105).
//
//   - intel.read: see the org's intel settings, the current feed, the org's
//     matches and contributions, and export the indicators as STIX.
//     Security Admin and Auditor hold it.
//   - intel.manage: set the consume mode and the share switch. Security
//     Admin holds it.
//   - intel.contribute: contribute an indicator made from a confirmed
//     finding. Security Admin holds it, and only a person can exercise it.
const (
	PermIntelRead       Permission = "intel.read"
	PermIntelManage     Permission = "intel.manage"
	PermIntelContribute Permission = "intel.contribute"
)

// m38IntelCatalog are the M38 intel permissions in catalog order.
var m38IntelCatalog = []Permission{PermIntelRead, PermIntelManage, PermIntelContribute}

func init() {
	catalog = append(catalog, m38IntelCatalog...)
	humanOnly = append(humanOnly, PermIntelManage, PermIntelContribute) // D1104a
	for i := range roles {
		r := &roles[i]
		switch r.Name { //nolint:exhaustive // only these roles gain the M38 intel permissions
		case RoleSecurityAdmin:
			r.Permissions = append(r.Permissions, PermIntelRead, PermIntelManage, PermIntelContribute)
			r.Description += " Sets how the org uses shared threat-intel indicators and contributes indicators from confirmed findings."
		case RoleAuditor:
			r.Permissions = append(r.Permissions, PermIntelRead)
			r.Description += " Reads shared threat-intel settings, matches and contributions."
		}
	}
}
