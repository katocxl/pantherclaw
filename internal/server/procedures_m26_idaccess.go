// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// idpAccessProcedures are IdpAccessService's procedures (G0 M26 D400,
// D402, D408): writes need identity_provider.manage and the use cases
// refuse every caller who is not a person; reads need
// identity_provider.read.
var idpAccessProcedures = map[string]td.Permission{
	pantherclawv1connect.IdpAccessServiceCreateAssertionIssuerProcedure:    td.PermIdentityProviderManage,
	pantherclawv1connect.IdpAccessServiceDisableAssertionIssuerProcedure:   td.PermIdentityProviderManage,
	pantherclawv1connect.IdpAccessServiceListAssertionIssuersProcedure:     td.PermIdentityProviderRead,
	pantherclawv1connect.IdpAccessServiceBindAssertionClientProcedure:      td.PermIdentityProviderManage,
	pantherclawv1connect.IdpAccessServiceRemoveAssertionClientProcedure:    td.PermIdentityProviderManage,
	pantherclawv1connect.IdpAccessServiceListAssertionClientsProcedure:     td.PermIdentityProviderRead,
	pantherclawv1connect.IdpAccessServiceGetMcpAccessProcedure:             td.PermIdentityProviderRead,
	pantherclawv1connect.IdpAccessServiceEnableMcpAccessProcedure:          td.PermIdentityProviderManage,
	pantherclawv1connect.IdpAccessServiceDisableMcpAccessProcedure:         td.PermIdentityProviderManage,
	pantherclawv1connect.IdpAccessServiceAllowMcpClientProcedure:           td.PermIdentityProviderManage,
	pantherclawv1connect.IdpAccessServiceRemoveMcpClientProcedure:          td.PermIdentityProviderManage,
	pantherclawv1connect.IdpAccessServiceRefreshMcpClientDocumentProcedure: td.PermIdentityProviderManage,
	pantherclawv1connect.IdpAccessServiceListMcpClientsProcedure:           td.PermIdentityProviderRead,
}

// idpAccessClasses are their plan-gate classes: turning something off stays
// possible on a lapsed plan (HR-141).
var idpAccessClasses = map[string]entitlements.Class{
	pantherclawv1connect.IdpAccessServiceCreateAssertionIssuerProcedure:    entitlements.ClassChange,
	pantherclawv1connect.IdpAccessServiceDisableAssertionIssuerProcedure:   entitlements.ClassSafety,
	pantherclawv1connect.IdpAccessServiceListAssertionIssuersProcedure:     entitlements.ClassRead,
	pantherclawv1connect.IdpAccessServiceBindAssertionClientProcedure:      entitlements.ClassChange,
	pantherclawv1connect.IdpAccessServiceRemoveAssertionClientProcedure:    entitlements.ClassSafety,
	pantherclawv1connect.IdpAccessServiceListAssertionClientsProcedure:     entitlements.ClassRead,
	pantherclawv1connect.IdpAccessServiceGetMcpAccessProcedure:             entitlements.ClassRead,
	pantherclawv1connect.IdpAccessServiceEnableMcpAccessProcedure:          entitlements.ClassChange,
	pantherclawv1connect.IdpAccessServiceDisableMcpAccessProcedure:         entitlements.ClassSafety,
	pantherclawv1connect.IdpAccessServiceAllowMcpClientProcedure:           entitlements.ClassChange,
	pantherclawv1connect.IdpAccessServiceRemoveMcpClientProcedure:          entitlements.ClassSafety,
	pantherclawv1connect.IdpAccessServiceRefreshMcpClientDocumentProcedure: entitlements.ClassChange,
	pantherclawv1connect.IdpAccessServiceListMcpClientsProcedure:           entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, idpAccessProcedures)
	maps.Copy(procedureClasses, idpAccessClasses)
}
