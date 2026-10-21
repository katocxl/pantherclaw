// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// uiTenancyProcedures are the hosted account procedures (G0 UI D8, D21):
// creating and listing the account's organizations. Their requirements
// belong to the signed-in account, never to a role (HR-350).
var uiTenancyProcedures = map[string]td.Permission{
	pantherclawv1connect.TenancyServiceCreateOrgProcedure:       td.PermOrgsCreate,
	pantherclawv1connect.TenancyServiceListMyOrgsProcedure:      td.PermOrgsListMine,
	pantherclawv1connect.AccessServiceAcceptInvitationProcedure: td.PermInvitationsAccept,
}

func init() { maps.Copy(procedurePermissions, uiTenancyProcedures) }
