// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// policyGateProcedures are PolicyService's publish-gate procedures (G0
// M11.1): validating and testing a version is policy.author, rolling back
// is policy.publish (human only, checked in the use case), and reading
// differences and change requests is policy.read. Confirming a change
// request has no procedure: only its page, with a security key.
var policyGateProcedures = map[string]td.Permission{
	pantherclawv1connect.PolicyServiceValidatePolicyVersionProcedure:    td.PermPolicyAuthor,
	pantherclawv1connect.PolicyServiceTestPolicyVersionProcedure:        td.PermPolicyAuthor,
	pantherclawv1connect.PolicyServiceDiffPolicyVersionsProcedure:       td.PermPolicyRead,
	pantherclawv1connect.PolicyServiceRollbackPolicyProcedure:           td.PermPolicyPublish,
	pantherclawv1connect.PolicyServiceListPolicyChangeRequestsProcedure: td.PermPolicyRead,
	pantherclawv1connect.PolicyServiceGetPolicyChangeRequestProcedure:   td.PermPolicyRead,
}

func init() { maps.Copy(procedurePermissions, policyGateProcedures) }
