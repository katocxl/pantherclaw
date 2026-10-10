// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// evidenceAdminProcedures are EvidenceAdminService's procedures (G0 M7
// track B, design decision 9). Each is human only; the use cases check
// the permission at org scope.
var evidenceAdminProcedures = map[string]td.Permission{
	pantherclawv1connect.EvidenceAdminServiceGetRetentionPoliciesProcedure: td.PermEvidenceRetentionManage,
	pantherclawv1connect.EvidenceAdminServiceSetRetentionPolicyProcedure:   td.PermEvidenceRetentionManage,
	pantherclawv1connect.EvidenceAdminServiceCreateLegalHoldProcedure:      td.PermEvidenceRetentionManage,
	pantherclawv1connect.EvidenceAdminServiceReleaseLegalHoldProcedure:     td.PermEvidenceRetentionManage,
	pantherclawv1connect.EvidenceAdminServiceListLegalHoldsProcedure:       td.PermEvidenceRetentionManage,
}

func init() { maps.Copy(procedurePermissions, evidenceAdminProcedures) }
