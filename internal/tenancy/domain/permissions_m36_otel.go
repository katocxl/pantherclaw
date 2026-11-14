// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M36 OTLP destination permissions (G0 M36 D1061; HR-786), as the SIEM
// destination permissions:
//
//   - otlp.read: see the org's OTLP destinations, their header names (never
//     values) and export health. Org Admin, Security Admin and Auditor
//     hold it.
//   - otlp.manage: create, activate (with a security key, on the page),
//     test and disable destinations. Security Admin holds it, as
//     siem.manage, and only a person can exercise it.
const (
	PermOTLPRead   Permission = "otlp.read"
	PermOTLPManage Permission = "otlp.manage"
)

// m36OTelCatalog are the M36 OTLP permissions in catalog order.
var m36OTelCatalog = []Permission{PermOTLPRead, PermOTLPManage}

func init() {
	catalog = append(catalog, m36OTelCatalog...)
	humanOnly = append(humanOnly, PermOTLPManage)
	for i := range roles {
		r := &roles[i]
		switch r.Name { //nolint:exhaustive // only these roles gain the M36 OTLP permissions
		case RoleSecurityAdmin:
			r.Permissions = append(r.Permissions, PermOTLPRead, PermOTLPManage)
			r.Description += " Sends the org's agent spans to its own OpenTelemetry collectors (activated with a security key)."
		case RoleOrgAdmin, RoleAuditor:
			r.Permissions = append(r.Permissions, PermOTLPRead)
			r.Description += " Reads the org's OpenTelemetry destinations and their export health."
		}
	}
}
