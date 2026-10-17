// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "slices"

// M14 permissions (G0 M14 D5).
//
//   - authzen.evaluate: ask the AuthZEN decision endpoint for a decision as
//     a registered enforcement point (D26). Service accounts only: a
//     person never holds it, whatever their bindings say, and only the
//     Enforcement Point role, bound only to service accounts, grants it.
//   - enforcement_point.manage: register, rebind and disable enforcement
//     points (D29). Org Admin holds it, and Org Admin stays bindable to
//     service accounts, so like github.identity.manage it is not in
//     humanOnly: the enforcement point service refuses any caller but a
//     person.
//   - a2a.peer_run.read: see the delegated runs peer agents made for
//     requesters (D33).
const (
	PermAuthZENEvaluate        Permission = "authzen.evaluate"
	PermEnforcementPointManage Permission = "enforcement_point.manage"
	PermA2APeerRunRead         Permission = "a2a.peer_run.read"
)

// m14Catalog are the M14 permissions in catalog order.
var m14Catalog = []Permission{PermAuthZENEvaluate, PermEnforcementPointManage, PermA2APeerRunRead}

// serviceOnly permissions are never held by a person (D5).
var serviceOnly = []Permission{PermAuthZENEvaluate}

// ServiceOnly reports whether only a service account may hold p.
func (p Permission) ServiceOnly() bool { return slices.Contains(serviceOnly, p) }
