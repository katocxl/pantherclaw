// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m21RecommendationProcedures are RecommendationService's procedures (G0
// M21 D302, D308): reading needs posture.read somewhere and the use case
// filters by scope; dismissing needs posture.manage, which the use case
// holds to org scope.
var m21RecommendationProcedures = map[string]td.Permission{
	pantherclawv1connect.RecommendationServiceListRecommendationsProcedure:     td.PermPostureRead,
	pantherclawv1connect.RecommendationServiceDismissRecommendationProcedure:   td.PermPostureManage,
	pantherclawv1connect.RecommendationServiceUndismissRecommendationProcedure: td.PermPostureManage,
}

func init() { maps.Copy(procedurePermissions, m21RecommendationProcedures) }
