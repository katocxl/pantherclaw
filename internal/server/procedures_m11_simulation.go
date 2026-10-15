// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// simulationProcedures are PolicySimulationService's procedures (G0 M11.1
// D15, HR-237): every one needs policy.simulate.
var simulationProcedures = map[string]td.Permission{
	pantherclawv1connect.PolicySimulationServiceSimulatePolicyVersionProcedure: td.PermPolicySimulate,
	pantherclawv1connect.PolicySimulationServiceGetSimulationProcedure:         td.PermPolicySimulate,
	pantherclawv1connect.PolicySimulationServiceListSimulationsProcedure:       td.PermPolicySimulate,
	pantherclawv1connect.PolicySimulationServiceCancelSimulationProcedure:      td.PermPolicySimulate,
	pantherclawv1connect.PolicySimulationServiceListSimulationSamplesProcedure: td.PermPolicySimulate,
}

func init() { maps.Copy(procedurePermissions, simulationProcedures) }
