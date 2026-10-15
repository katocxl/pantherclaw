// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// policyExceptionProcedures are PolicyExceptionService's procedures (G0
// M11.1 D14): asking needs policy.exception.request, revoking
// policy.publish (both a person only, checked by the use case); reads are
// policy reads.
var policyExceptionProcedures = map[string]td.Permission{
	pantherclawv1connect.PolicyExceptionServiceRequestPolicyExceptionProcedure: td.PermPolicyExceptionRequest,
	pantherclawv1connect.PolicyExceptionServiceGetPolicyExceptionProcedure:     td.PermPolicyRead,
	pantherclawv1connect.PolicyExceptionServiceListPolicyExceptionsProcedure:   td.PermPolicyRead,
	pantherclawv1connect.PolicyExceptionServiceRevokePolicyExceptionProcedure:  td.PermPolicyPublish,
}

func init() { maps.Copy(procedurePermissions, policyExceptionProcedures) }
