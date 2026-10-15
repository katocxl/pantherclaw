// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// policyRolloutProcedures are PolicyRolloutService's procedures (G0 M11.1,
// D12, D13): every change is policy.publish (human only), reads are
// policy.read.
var policyRolloutProcedures = map[string]td.Permission{
	pantherclawv1connect.PolicyRolloutServiceStartPolicyRolloutProcedure:         td.PermPolicyPublish,
	pantherclawv1connect.PolicyRolloutServiceStartPolicyPilotProcedure:           td.PermPolicyPublish,
	pantherclawv1connect.PolicyRolloutServiceExpandPolicyPilotProcedure:          td.PermPolicyPublish,
	pantherclawv1connect.PolicyRolloutServiceExcludePolicyRolloutTargetProcedure: td.PermPolicyPublish,
	pantherclawv1connect.PolicyRolloutServiceCompletePolicyRolloutProcedure:      td.PermPolicyPublish,
	pantherclawv1connect.PolicyRolloutServiceCancelPolicyRolloutProcedure:        td.PermPolicyPublish,
	pantherclawv1connect.PolicyRolloutServiceGetPolicyRolloutProcedure:           td.PermPolicyRead,
	pantherclawv1connect.PolicyRolloutServiceListPolicyRolloutsProcedure:         td.PermPolicyRead,
	pantherclawv1connect.PolicyRolloutServiceListPolicyRolloutTargetsProcedure:   td.PermPolicyRead,
	pantherclawv1connect.PolicyRolloutServiceCreatePolicyCohortProcedure:         td.PermPolicyPublish,
	pantherclawv1connect.PolicyRolloutServiceAddPolicyCohortMembersProcedure:     td.PermPolicyPublish,
	pantherclawv1connect.PolicyRolloutServiceRemovePolicyCohortMembersProcedure:  td.PermPolicyPublish,
	pantherclawv1connect.PolicyRolloutServiceListPolicyCohortsProcedure:          td.PermPolicyRead,
	pantherclawv1connect.PolicyRolloutServiceGetShadowSummaryProcedure:           td.PermPolicyRead,
}

func init() { maps.Copy(procedurePermissions, policyRolloutProcedures) }
