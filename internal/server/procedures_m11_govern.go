// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/cohorts"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/promotions"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m11GovernProcedures are PromotionService's, CohortService's and
// PackService's procedures (G0 M11 part 2, D39–D41): promoting and cohort
// changes are human only; reads are agent.read, packs policy.read, and
// applying a pack is policy.author (it only drafts).
var m11GovernProcedures = map[string]td.Permission{
	pantherclawv1connect.PromotionServicePromoteAgentProcedure:    promotions.PermPromote,
	pantherclawv1connect.PromotionServiceRevokePromotionProcedure: promotions.PermPromote,
	pantherclawv1connect.PromotionServiceGetReadinessProcedure:    td.PermAgentRead,
	pantherclawv1connect.PromotionServiceListPromotionsProcedure:  td.PermAgentRead,

	pantherclawv1connect.CohortServiceCreateFleetCohortProcedure:        cohorts.PermManage,
	pantherclawv1connect.CohortServiceUpdateFleetCohortProcedure:        cohorts.PermManage,
	pantherclawv1connect.CohortServiceDeleteFleetCohortProcedure:        cohorts.PermManage,
	pantherclawv1connect.CohortServiceGetFleetCohortProcedure:           td.PermAgentRead,
	pantherclawv1connect.CohortServiceListFleetCohortsProcedure:         td.PermAgentRead,
	pantherclawv1connect.CohortServiceListFleetCohortMembersProcedure:   td.PermAgentRead,
	pantherclawv1connect.CohortServiceAddFleetCohortMembersProcedure:    cohorts.PermManage,
	pantherclawv1connect.CohortServiceRemoveFleetCohortMembersProcedure: cohorts.PermManage,
	pantherclawv1connect.CohortServiceSetAgentTaskTypeProcedure:         cohorts.PermManage,
	pantherclawv1connect.CohortServiceGetCohortQueueProcedure:           td.PermAgentRead,
	pantherclawv1connect.CohortServiceGetCohortChangesProcedure:         td.PermAgentRead,
	pantherclawv1connect.CohortServiceGetFleetOverviewProcedure:         td.PermAgentRead,

	pantherclawv1connect.PackServiceListPacksProcedure: td.PermPolicyRead,
	pantherclawv1connect.PackServiceGetPackProcedure:   td.PermPolicyRead,
	pantherclawv1connect.PackServiceApplyPackProcedure: td.PermPolicyAuthor,
}

func init() { maps.Copy(procedurePermissions, m11GovernProcedures) }
