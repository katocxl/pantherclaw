// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// responseProcedures are ResponseService's procedures (G0 M10 D21–D26):
// containing, terminating, revoking and asking for a restoration need
// incident.respond; deciding and applying a restoration agent.restore; a
// SOAR request response.request; reads containment.read. The use cases add
// the scope's path, people-only rules and step-ups.
var responseProcedures = map[string]td.Permission{
	pantherclawv1connect.ResponseServicePreviewContainmentProcedure:      td.PermContainmentRead,
	pantherclawv1connect.ResponseServiceContainProcedure:                 td.PermIncidentRespond,
	pantherclawv1connect.ResponseServiceProposeResponseProcedure:         td.PermContainmentRead,
	pantherclawv1connect.ResponseServiceTerminateRunProcedure:            td.PermIncidentRespond,
	pantherclawv1connect.ResponseServicePreviewCredentialChangeProcedure: td.PermContainmentRead,
	pantherclawv1connect.ResponseServiceRevokeSealedCredentialProcedure:  td.PermIncidentRespond,
	pantherclawv1connect.ResponseServiceRotateSealedCredentialProcedure:  td.PermIncidentRespond,
	pantherclawv1connect.ResponseServiceRequestControlProcedure:          td.PermResponseRequest,
	pantherclawv1connect.ResponseServiceRequestRestorationProcedure:      td.PermIncidentRespond,
	pantherclawv1connect.ResponseServiceDecideRestorationProcedure:       td.PermAgentRestore,
	pantherclawv1connect.ResponseServiceApplyRestorationStageProcedure:   td.PermAgentRestore,
	pantherclawv1connect.ResponseServiceDecideContainmentHoldProcedure:   td.PermIncidentRespond,
	pantherclawv1connect.ResponseServiceGetResponseActionProcedure:       td.PermContainmentRead,
	pantherclawv1connect.ResponseServiceListResponseActionsProcedure:     td.PermContainmentRead,
	pantherclawv1connect.ResponseServiceListContainmentControlsProcedure: td.PermContainmentRead,
	pantherclawv1connect.ResponseServiceGetRestorationPlanProcedure:      td.PermContainmentRead,
}

func init() { maps.Copy(procedurePermissions, responseProcedures) }
