// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// identityProviderProcedures are IdentityProviderService's procedures (G0
// M18 D155, D161): writes need identity_provider.manage and the use cases
// refuse every caller who is not a person; reads need
// identity_provider.read.
var identityProviderProcedures = map[string]td.Permission{
	pantherclawv1connect.IdentityProviderServiceCreateIdentityProviderProcedure:  td.PermIdentityProviderManage,
	pantherclawv1connect.IdentityProviderServiceUpdateIdentityProviderProcedure:  td.PermIdentityProviderManage,
	pantherclawv1connect.IdentityProviderServiceDisableIdentityProviderProcedure: td.PermIdentityProviderManage,
	pantherclawv1connect.IdentityProviderServiceSetOwnProvidersOnlyProcedure:     td.PermIdentityProviderManage,
	pantherclawv1connect.IdentityProviderServiceGetIdentityProviderProcedure:     td.PermIdentityProviderRead,
	pantherclawv1connect.IdentityProviderServiceListIdentityProvidersProcedure:   td.PermIdentityProviderRead,
}

func init() { maps.Copy(procedurePermissions, identityProviderProcedures) }
