// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m25ComplianceProcedures are ComplianceService's procedures (G0 M25 D311):
// reading coverage needs compliance.read, and each source its own permission
// (D312). A report's export is CreateEvidencePack, which stays ClassSafety.
var m25ComplianceProcedures = map[string]td.Permission{
	pantherclawv1connect.ComplianceServiceListFrameworksProcedure:        td.PermComplianceRead,
	pantherclawv1connect.ComplianceServiceGetFrameworkCoverageProcedure:  td.PermComplianceRead,
	pantherclawv1connect.ComplianceServiceListComplianceReportsProcedure: td.PermComplianceRead,
}

func init() {
	maps.Copy(procedurePermissions, m25ComplianceProcedures)
	for p := range m25ComplianceProcedures {
		procedureClasses[p] = entitlements.ClassRead
	}
}
