// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// reflexCoreProcedures are IncidentService's and DetectionService's
// procedures (G0 M10 D4). Reads are filtered by where their agents live
// (D8); managing is for people only, checked by the use cases.
var reflexCoreProcedures = map[string]td.Permission{
	pantherclawv1connect.IncidentServiceListAlertsProcedure:          td.PermIncidentRead,
	pantherclawv1connect.IncidentServiceGetAlertProcedure:            td.PermIncidentRead,
	pantherclawv1connect.IncidentServiceSetAlertStateProcedure:       td.PermIncidentManage,
	pantherclawv1connect.IncidentServicePromoteAlertProcedure:        td.PermIncidentManage,
	pantherclawv1connect.IncidentServiceLinkAlertProcedure:           td.PermIncidentManage,
	pantherclawv1connect.IncidentServiceListIncidentsProcedure:       td.PermIncidentRead,
	pantherclawv1connect.IncidentServiceGetIncidentProcedure:         td.PermIncidentRead,
	pantherclawv1connect.IncidentServiceAssignIncidentProcedure:      td.PermIncidentManage,
	pantherclawv1connect.IncidentServiceSetIncidentStateProcedure:    td.PermIncidentManage,
	pantherclawv1connect.IncidentServiceCreateSuppressionProcedure:   td.PermIncidentManage,
	pantherclawv1connect.IncidentServiceListSuppressionsProcedure:    td.PermIncidentRead,
	pantherclawv1connect.IncidentServiceEndSuppressionProcedure:      td.PermIncidentManage,
	pantherclawv1connect.IncidentServiceListFailuresProcedure:        td.PermIncidentRead,
	pantherclawv1connect.IncidentServiceAssignFailureProcedure:       td.PermIncidentManage,
	pantherclawv1connect.IncidentServiceResolveFailureProcedure:      td.PermIncidentManage,
	pantherclawv1connect.DetectionServiceListRulesProcedure:          td.PermDetectionRead,
	pantherclawv1connect.DetectionServiceGetDetectionStatusProcedure: td.PermDetectionRead,
	pantherclawv1connect.DetectionServiceCreateCustomRuleProcedure:   td.PermDetectionManage,
	pantherclawv1connect.DetectionServiceTestCustomRuleProcedure:     td.PermDetectionManage,
	pantherclawv1connect.DetectionServicePublishCustomRuleProcedure:  td.PermDetectionManage,
	pantherclawv1connect.DetectionServiceDisableCustomRuleProcedure:  td.PermDetectionManage,
	pantherclawv1connect.DetectionServiceEnableRuleProcedure:         td.PermDetectionManage,
}

func init() { maps.Copy(procedurePermissions, reflexCoreProcedures) }
