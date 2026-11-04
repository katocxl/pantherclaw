// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// IsInvestigator reports whether the caller holds the Investigator role at
// any scope (G0 M27 D510, HR-655).
func IsInvestigator(c Caller) bool {
	return slices.ContainsFunc(c.Bindings, func(b domain.Binding) bool { return b.Role == domain.RoleInvestigator })
}

// WithoutInvestigator is the caller as its other bindings leave it. The role
// counts on the five reads behind pclaw mcp self and nowhere else (HR-655):
// every route outside them, Connect or plain HTTP, sees this caller. The
// bindings are cloned, so c is not changed.
func WithoutInvestigator(c Caller) Caller {
	if !IsInvestigator(c) {
		return c
	}
	c.Bindings = slices.DeleteFunc(slices.Clone(c.Bindings), func(b domain.Binding) bool { return b.Role == domain.RoleInvestigator })
	return c
}
