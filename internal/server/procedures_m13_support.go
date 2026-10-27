// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// supportProcedures are SupportAccessService's and BreakGlassService's
// procedures (G0 M13 D32, D33, D38). Asking for access, opening a support
// session, approving, denying and activating break-glass need a
// security-key step-up and answer STEP_UP_REQUIRED here: they happen on
// their server pages. The staff procedures declare authenticated; their
// use cases refuse anyone who is not support staff.
var supportProcedures = map[string]td.Permission{
	pantherclawv1connect.SupportAccessServiceRequestSupportAccessProcedure:     td.PermAuthenticated,
	pantherclawv1connect.SupportAccessServiceOpenSupportSessionProcedure:       td.PermAuthenticated,
	pantherclawv1connect.SupportAccessServiceGetCurrentSupportSessionProcedure: td.PermAuthenticated,
	pantherclawv1connect.SupportAccessServiceListSupportRequestsProcedure:      td.PermSupportRead,
	pantherclawv1connect.SupportAccessServiceGetSupportRequestProcedure:        td.PermSupportRead,
	pantherclawv1connect.SupportAccessServiceApproveSupportRequestProcedure:    td.PermSupportManage,
	pantherclawv1connect.SupportAccessServiceDenySupportRequestProcedure:       td.PermSupportManage,
	pantherclawv1connect.SupportAccessServiceListSupportGrantsProcedure:        td.PermSupportRead,
	pantherclawv1connect.SupportAccessServiceRevokeSupportGrantProcedure:       td.PermSupportManage,
	pantherclawv1connect.BreakGlassServiceListBreakGlassHoldersProcedure:       td.PermBreakGlassRead,
	pantherclawv1connect.BreakGlassServiceSetBreakGlassHoldersProcedure:        td.PermBreakGlassManage,
	pantherclawv1connect.BreakGlassServiceActivateBreakGlassProcedure:          td.PermAuthenticated,
	pantherclawv1connect.BreakGlassServiceEndBreakGlassProcedure:               td.PermAuthenticated,
	pantherclawv1connect.BreakGlassServiceGetMyBreakGlassProcedure:             td.PermAuthenticated,
	pantherclawv1connect.BreakGlassServiceListBreakGlassActivationsProcedure:   td.PermBreakGlassRead,
}

func init() { maps.Copy(procedurePermissions, supportProcedures) }
