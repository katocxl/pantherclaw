// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m13DataProcedures are DataRequestService's procedures and
// AccountService.DeleteAccount (G0 M13 D34): the org's export and
// deletion, and the hosted account's own deletion and deletion records.
// account.delete and deletion_records.read belong to the signed-in
// account, never to a role (HR-350).
var m13DataProcedures = map[string]td.Permission{
	pantherclawv1connect.DataRequestServiceCreateExportProcedure:      td.PermDataExport,
	pantherclawv1connect.DataRequestServiceGetDataRequestProcedure:    td.PermDataRequestsRead,
	pantherclawv1connect.DataRequestServiceListDataRequestsProcedure:  td.PermDataRequestsRead,
	pantherclawv1connect.DataRequestServiceDownloadExportProcedure:    td.PermDataExport,
	pantherclawv1connect.DataRequestServiceRequestDeletionProcedure:   td.PermOrgDelete,
	pantherclawv1connect.DataRequestServiceCancelDeletionProcedure:    td.PermOrgDelete,
	pantherclawv1connect.DataRequestServiceGetDeletionRecordProcedure: td.PermDeletionRecordsRead,
	pantherclawv1connect.AccountServiceDeleteAccountProcedure:         td.PermAccountDelete,
}

func init() { maps.Copy(procedurePermissions, m13DataProcedures) }
