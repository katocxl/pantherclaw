// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m26ProvisioningProcedures are ProvisioningService's procedures (G0 M26
// D405, D406, D409): writes need identity_provider.manage and the use cases
// refuse every caller who is not a person; reads need
// identity_provider.read.
var m26ProvisioningProcedures = map[string]td.Permission{
	pantherclawv1connect.ProvisioningServiceCreateScimTokenProcedure:        td.PermIdentityProviderManage,
	pantherclawv1connect.ProvisioningServiceRevokeScimTokenProcedure:        td.PermIdentityProviderManage,
	pantherclawv1connect.ProvisioningServiceListScimTokensProcedure:         td.PermIdentityProviderRead,
	pantherclawv1connect.ProvisioningServiceCreateSamlConnectionProcedure:   td.PermIdentityProviderManage,
	pantherclawv1connect.ProvisioningServiceUpdateSamlConnectionProcedure:   td.PermIdentityProviderManage,
	pantherclawv1connect.ProvisioningServiceDisableSamlConnectionProcedure:  td.PermIdentityProviderManage,
	pantherclawv1connect.ProvisioningServiceListSamlConnectionsProcedure:    td.PermIdentityProviderRead,
	pantherclawv1connect.ProvisioningServiceListGroupsProcedure:             td.PermIdentityProviderRead,
	pantherclawv1connect.ProvisioningServiceListGroupRoleMappingsProcedure:  td.PermIdentityProviderRead,
	pantherclawv1connect.ProvisioningServiceAddGroupRoleMappingProcedure:    td.PermIdentityProviderManage,
	pantherclawv1connect.ProvisioningServiceRemoveGroupRoleMappingProcedure: td.PermIdentityProviderManage,
}

// m26ProvisioningClasses: revoking, disabling and removing a mapping take
// authority away, so a lapsed plan keeps them (D409 point 7).
var m26ProvisioningClasses = map[string]entitlements.Class{
	pantherclawv1connect.ProvisioningServiceCreateScimTokenProcedure:        entitlements.ClassChange,
	pantherclawv1connect.ProvisioningServiceRevokeScimTokenProcedure:        entitlements.ClassSafety,
	pantherclawv1connect.ProvisioningServiceListScimTokensProcedure:         entitlements.ClassRead,
	pantherclawv1connect.ProvisioningServiceCreateSamlConnectionProcedure:   entitlements.ClassChange,
	pantherclawv1connect.ProvisioningServiceUpdateSamlConnectionProcedure:   entitlements.ClassChange,
	pantherclawv1connect.ProvisioningServiceDisableSamlConnectionProcedure:  entitlements.ClassSafety,
	pantherclawv1connect.ProvisioningServiceListSamlConnectionsProcedure:    entitlements.ClassRead,
	pantherclawv1connect.ProvisioningServiceListGroupsProcedure:             entitlements.ClassRead,
	pantherclawv1connect.ProvisioningServiceListGroupRoleMappingsProcedure:  entitlements.ClassRead,
	pantherclawv1connect.ProvisioningServiceAddGroupRoleMappingProcedure:    entitlements.ClassChange,
	pantherclawv1connect.ProvisioningServiceRemoveGroupRoleMappingProcedure: entitlements.ClassSafety,
}

func init() {
	maps.Copy(procedurePermissions, m26ProvisioningProcedures)
	maps.Copy(procedureClasses, m26ProvisioningClasses)
}
