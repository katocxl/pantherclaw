// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M18 permissions (G0 M18 D161). The fleet (S18a), large-fleet (S18c) and
// Scope Admin (D152) features reuse existing permissions; only the
// organization's own identity providers (PN-012.7, D155) add new ones.
//
//   - identity_provider.read: see the org's identity providers, never their
//     client secrets (HR-482). Org Admin, Security Admin and Auditor hold
//     it.
//   - identity_provider.manage: propose creating, changing or disabling one
//     and the "own providers only" setting, each a two-person protected
//     change (HR-481). Only Org Admin holds it. It is for people only, but
//     Org Admin stays bindable to service accounts, so like
//     enforcement_point.manage it is not in humanOnly: the identity
//     provider service refuses any caller but a person.
const (
	PermIdentityProviderRead   Permission = "identity_provider.read"
	PermIdentityProviderManage Permission = "identity_provider.manage"
)

// m18Catalog are the M18 permissions in catalog order.
var m18Catalog = []Permission{PermIdentityProviderRead, PermIdentityProviderManage}
