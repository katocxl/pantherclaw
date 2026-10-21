// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR387_ASupportSessionNeverCallsAChange: across every org procedure,
// a support session may call only the plan gate's reads and the few
// read-only lookups of who it is; never a change or a safety action.
func TestHR387_ASupportSessionNeverCallsAChange(t *testing.T) {
	allowed := 0
	for p, perm := range procedurePermissions {
		if !supportMayCall(p) {
			continue
		}
		allowed++
		c := procedureClass(p)
		if c != entitlements.ClassRead && !supportReadOnly[p] {
			t.Errorf("%s (%s) is callable by a support session", p, c)
		}
		if perm != td.PermAuthenticated && perm != td.PermPublic && !perm.Known() {
			t.Errorf("%s declares %s", p, perm)
		}
	}
	if allowed < 50 {
		t.Fatalf("only %d procedures are reads for support", allowed)
	}
	for _, p := range []string{
		pantherclawv1connect.AccessServiceCreateRoleBindingProcedure,
		pantherclawv1connect.AccessServiceSetUserStateProcedure,
		pantherclawv1connect.AgentServiceUpdateAgentProcedure,
		pantherclawv1connect.SupportAccessServiceRevokeSupportGrantProcedure,
		pantherclawv1connect.SupportAccessServiceApproveSupportRequestProcedure,
		pantherclawv1connect.BreakGlassServiceActivateBreakGlassProcedure,
		pantherclawv1connect.AccountServiceRevokeMySessionProcedure,
		pantherclawv1connect.TenancyServiceCreateOrgProcedure,
	} {
		if supportMayCall(p) {
			t.Errorf("a support session may call %s", p)
		}
	}
	for p := range supportReadOnly {
		if procedureClass(p) == entitlements.ClassChange || procedureClass(p) == entitlements.ClassSafety {
			t.Errorf("%s is a change", p)
		}
	}
}
