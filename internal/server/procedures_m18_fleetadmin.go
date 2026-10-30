// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fleetAdminProcedures are the M18 large-fleet procedures (G0 M18 D154,
// D161): exception groups reuse the exception permissions (asking needs
// policy.exception.request, revoking policy.publish, both a person only,
// checked by the use case; reads are policy reads), and per-cohort
// findings are agent reads (each kind checks its own read again). The
// Enterprise gate (LargeFleetAdmin) is checked by the use cases.
var fleetAdminProcedures = map[string]td.Permission{
	pantherclawv1connect.PolicyExceptionServiceRequestPolicyExceptionGroupProcedure: td.PermPolicyExceptionRequest,
	pantherclawv1connect.PolicyExceptionServiceGetPolicyExceptionGroupProcedure:     td.PermPolicyRead,
	pantherclawv1connect.PolicyExceptionServiceListPolicyExceptionGroupsProcedure:   td.PermPolicyRead,
	pantherclawv1connect.PolicyExceptionServiceRevokePolicyExceptionGroupProcedure:  td.PermPolicyPublish,
	pantherclawv1connect.CohortServiceGetCohortFindingsProcedure:                    td.PermAgentRead,
}

// fleetAdminClasses are their plan-gate classes (G0 UI D43, HR-356), kept
// here beside them: revoking a group reduces authority.
var fleetAdminClasses = map[string]entitlements.Class{
	pantherclawv1connect.PolicyExceptionServiceRequestPolicyExceptionGroupProcedure: entitlements.ClassChange,
	pantherclawv1connect.PolicyExceptionServiceGetPolicyExceptionGroupProcedure:     entitlements.ClassRead,
	pantherclawv1connect.PolicyExceptionServiceListPolicyExceptionGroupsProcedure:   entitlements.ClassRead,
	pantherclawv1connect.PolicyExceptionServiceRevokePolicyExceptionGroupProcedure:  entitlements.ClassSafety,
	pantherclawv1connect.CohortServiceGetCohortFindingsProcedure:                    entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, fleetAdminProcedures)
	maps.Copy(procedureClasses, fleetAdminClasses)
}
