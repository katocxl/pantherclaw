// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// exposureProcedures are ExposureService's, GraphService's and
// PostureService's procedures (G0 M10 D4, D27–D31): reads need
// exposure.read or posture.read, the posture lifecycle posture.manage; the
// use cases check them again where each agent lives (D8).
var exposureProcedures = map[string]td.Permission{
	pantherclawv1connect.ExposureServiceGetExposureProcedure:              td.PermExposureRead,
	pantherclawv1connect.ExposureServiceGetReachMatrixProcedure:           td.PermExposureRead,
	pantherclawv1connect.ExposureServiceRankExposureProcedure:             td.PermExposureRead,
	pantherclawv1connect.ExposureServiceListCredentialDependentsProcedure: td.PermExposureRead,
	pantherclawv1connect.ExposureServicePreviewReductionProcedure:         td.PermExposureRead,
	pantherclawv1connect.GraphServiceGetGraphProcedure:                    td.PermExposureRead,
	pantherclawv1connect.GraphServiceListGraphEdgesProcedure:              td.PermExposureRead,

	pantherclawv1connect.PostureServiceListPostureFindingsProcedure:           td.PermPostureRead,
	pantherclawv1connect.PostureServiceListPostureRootCausesProcedure:         td.PermPostureRead,
	pantherclawv1connect.PostureServiceGetPostureFindingProcedure:             td.PermPostureRead,
	pantherclawv1connect.PostureServiceAssignPostureFindingProcedure:          td.PermPostureManage,
	pantherclawv1connect.PostureServiceStartPostureTestingProcedure:           td.PermPostureManage,
	pantherclawv1connect.PostureServiceAcceptPostureFindingProcedure:          td.PermPostureManage,
	pantherclawv1connect.PostureServiceMarkPostureEvidenceIncompleteProcedure: td.PermPostureManage,
	pantherclawv1connect.PostureServiceReopenPostureFindingProcedure:          td.PermPostureManage,
	pantherclawv1connect.PostureServiceAddPostureNoteProcedure:                td.PermPostureManage,
}

func init() { maps.Copy(procedurePermissions, exposureProcedures) }
