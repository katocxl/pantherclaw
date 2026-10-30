// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"

// ErrBindingCeiling refuses a binding or unbinding above the caller's
// ceiling: a caller without org-level role.bind binds and unbinds only roles
// it holds at the target scope or an ancestor (G0 M18 D152, HR-472..474).
var ErrBindingCeiling = pcerr.New(pcerr.PermissionDenied, "BINDING_CEILING",
	"you can bind and unbind only roles you hold at that scope or above")

// CheckBindCeiling decides whether the subject may bind or unbind role at
// the scope ending target, the scope's path in the current hierarchy
// (G0 M18 D152):
//   - role.bind is required on target;
//   - org-level role.bind binds any role anywhere in the org;
//   - otherwise the target must be below the org (an org-scope binding needs
//     org-level role.bind, HR-473), and the subject must hold a binding of
//     the same role on target, at the target scope or an ancestor (HR-472).
//     A Scope Admin may therefore re-delegate Scope Admin below its scope.
func (s Subject) CheckBindCeiling(role RoleName, target Path) error {
	if err := s.Require(PermRoleBind, target); err != nil {
		return err
	}
	if s.Can(PermRoleBind, OrgPath(s.Org)) {
		return nil
	}
	if len(target) < 2 {
		return ErrBindingCeiling
	}
	for _, b := range s.Bindings {
		if b.Role == role && b.BreakGlass.IsZero() && target.Contains(b.Scope) {
			return nil
		}
	}
	return ErrBindingCeiling
}
