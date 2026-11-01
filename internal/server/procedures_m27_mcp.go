// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// selfMCPReads is the closed set of reads behind pclaw mcp self (G0 M27 D510,
// HR-655). The Investigator role counts on these and on nothing else: the
// permissions it needs for them also declare writes (search.read on the saved
// queries and on model drafting, evidence.read on bundle export), and the
// handlers check those same permissions, so holding fewer is not possible.
// selfMCPGate closes the difference.
var selfMCPReads = []string{
	pantherclawv1connect.InvestigationServiceWhatHappenedProcedure,
	pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure,
	pantherclawv1connect.SearchServiceSearchProcedure,
	pantherclawv1connect.GraphServiceGetGraphProcedure,
}

// isInvestigator reports whether the caller holds the role at any scope.
func isInvestigator(c tapp.Caller) bool {
	return slices.ContainsFunc(c.Bindings, func(b td.Binding) bool { return b.Role == td.RoleInvestigator })
}

// withoutInvestigator is the caller as its other bindings leave it.
func withoutInvestigator(c tapp.Caller) tapp.Caller {
	c.Bindings = slices.DeleteFunc(slices.Clone(c.Bindings), func(b td.Binding) bool { return b.Role == td.RoleInvestigator })
	return c
}

// procedureAdmits is the interceptor's question for one caller: does what it
// holds get it past rpcauth on the procedure?
func procedureAdmits(c tapp.Caller, procedure string) bool {
	perm, ok := procedurePermissions[procedure]
	switch {
	case !ok:
		return false
	case perm == td.PermAuthenticated:
		return len(c.Bindings) > 0
	case c.CanAnywhere(perm):
		return true
	}
	alt, ok := m24AlternatePermissions[procedure]
	return ok && c.CanAnywhere(alt)
}
