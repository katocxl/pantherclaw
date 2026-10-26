// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M13 data permissions (G0 M13 D34; HR-390..394).
//
//   - data.export: export the whole org and download the export.
//   - data_requests.read: read the org's exports and deletion requests.
//   - org.delete: request or cancel the deletion of the whole org.
//
// All three are Org Admin only; the use cases refuse service accounts and
// API keys (Org Admin stays bindable to service accounts). The account
// requirements are declarable only, never granted by a role (HR-350):
//
//   - account.delete: delete the signed-in hosted account.
//   - deletion_records.read: read the deletion record of an org the
//     account asked to delete.
const (
	PermDataExport          Permission = "data.export"
	PermDataRequestsRead    Permission = "data_requests.read"
	PermOrgDelete           Permission = "org.delete"
	PermAccountDelete       Permission = "account.delete"
	PermDeletionRecordsRead Permission = "deletion_records.read"
)

// m13DataCatalog are the M13 data permissions in catalog order.
var m13DataCatalog = []Permission{PermDataExport, PermDataRequestsRead, PermOrgDelete}

// m13DataAccountOnly are the M13 data account requirements.
var m13DataAccountOnly = []Permission{PermAccountDelete, PermDeletionRecordsRead}

func init() {
	for i := range roles {
		r := &roles[i]
		if r.Name == RoleOrgAdmin {
			r.Permissions = append(r.Permissions, m13DataCatalog...)
			r.Description += " Exports the whole org and requests its deletion."
		}
	}
}
