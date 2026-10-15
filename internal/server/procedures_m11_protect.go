// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// protectProcedures are ProtectedChangeService's and PublisherService's
// procedures (G0 M11 part 2 D42, D43): settings and the change list need
// protected_change.manage, an emergency change incident.respond, every
// publisher procedure publisher.compromise. The use cases add the
// people-only rules, the step-ups and the edition.
var protectProcedures = map[string]td.Permission{
	pantherclawv1connect.ProtectedChangeServiceGetProtectedChangeSettingsProcedure:    td.PermProtectedChangeManage,
	pantherclawv1connect.ProtectedChangeServiceSetProtectedCategoryModeProcedure:      td.PermProtectedChangeManage,
	pantherclawv1connect.ProtectedChangeServiceListProtectedChangesProcedure:          td.PermProtectedChangeManage,
	pantherclawv1connect.ProtectedChangeServiceApplyEmergencyProtectedChangeProcedure: td.PermIncidentRespond,
	pantherclawv1connect.PublisherServiceMarkCompromisedProcedure:                     td.PermPublisherCompromise,
	pantherclawv1connect.PublisherServiceListCompromisesProcedure:                     td.PermPublisherCompromise,
	pantherclawv1connect.PublisherServiceListExposedProcedure:                         td.PermPublisherCompromise,
	pantherclawv1connect.PublisherServiceReviewExposedProcedure:                       td.PermPublisherCompromise,
	pantherclawv1connect.PublisherServiceClearCompromiseProcedure:                     td.PermPublisherCompromise,
}

func init() { maps.Copy(procedurePermissions, protectProcedures) }
