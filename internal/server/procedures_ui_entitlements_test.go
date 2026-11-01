// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// gateExempt reports procedures the plan gate never sees: public ones,
// gateway and workload procedures (HR-357: protection never depends on the
// plan) and the account procedures.
func gateExempt(p td.Permission) bool {
	exempt := []td.Permission{
		td.PermPublic, td.PermOrgsCreate, td.PermOrgsListMine, td.PermInvitationsAccept, td.PermGatewayEnroll,
		td.PermAccountDelete, td.PermDeletionRecordsRead, td.PermHostingAgent,
	}
	return slices.Contains(exempt, p) || p.Gateway() || p.Workload()
}

// TestEveryOrgProcedureIsClassified (G0 UI D43, HR-356): every org
// procedure has a class, and no other procedure has one.
func TestEveryOrgProcedureIsClassified(t *testing.T) {
	for proc, perm := range procedurePermissions {
		c, ok := procedureClasses[proc]
		switch {
		case gateExempt(perm) && ok:
			t.Errorf("%s (%s) is never gated but has class %s", proc, perm, c)
		case !gateExempt(perm) && !ok:
			t.Errorf("%s (%s) has no plan-gate class", proc, perm)
		}
	}
	for proc := range procedureClasses {
		if _, ok := procedurePermissions[proc]; !ok {
			t.Errorf("%s is classified but not served", proc)
		}
	}
}

// TestPlanGateClassesAreSound: reads are read-shaped, the D9 allow list is
// exactly the listed procedures, and the actions HR-357 keeps working are
// never changes.
func TestPlanGateClassesAreSound(t *testing.T) {
	allow := map[string]bool{}
	for proc, c := range procedureClasses {
		method := proc[strings.LastIndex(proc, "/")+1:]
		if c == entitlements.ClassAllow {
			allow[proc] = true
		}
		for _, v := range []string{"Create", "Update", "Publish", "Enroll", "Issue", "Register", "Import"} {
			if strings.HasPrefix(method, v) && c == entitlements.ClassRead {
				t.Errorf("%s is a %s but classified read", proc, v)
			}
		}
	}
	for _, p := range []string{
		"/pantherclaw.v1.AccessService/WhoAmI", "/pantherclaw.v1.TenancyService/GetOrg", "/pantherclaw.v1.TenancyService/UpdateOrg",
		"/pantherclaw.v1.EntitlementService/GetEntitlements", "/pantherclaw.v1.OnboardingService/GetProgress",
	} {
		if !allow[p] {
			t.Errorf("%s is not on the allow list (D9)", p)
		}
	}
	for proc := range allow {
		if !strings.Contains(proc, ".AccountService/") && !strings.Contains(proc, ".AccessService/WhoAmI") &&
			!strings.Contains(proc, ".TenancyService/GetOrg") && !strings.Contains(proc, ".TenancyService/UpdateOrg") &&
			!strings.Contains(proc, ".EntitlementService/") && !strings.Contains(proc, ".OnboardingService/GetProgress") {
			t.Errorf("%s is on the allow list but D9 does not name it", proc)
		}
	}
	// HR-357: the kill switch, containment and open approvals keep working
	// on a lapsed plan.
	for _, p := range []string{
		"/pantherclaw.v1.ResponseService/Contain", "/pantherclaw.v1.ResponseService/TerminateRun",
		"/pantherclaw.v1.AgentService/SuspendAgent", "/pantherclaw.v1.ApprovalService/DeclineApprovalRequest",
		"/pantherclaw.v1.GrantService/RevokeGrant", "/pantherclaw.v1.EvidenceService/CreateEvidencePack",
		"/pantherclaw.v1.ReconciliationService/ResolveOccurred", "/pantherclaw.v1.ConnectionService/QuarantineConnection",
		"/pantherclaw.v1.RunService/StartRun",              // D88: existing agents keep running under enforcement
		"/pantherclaw.v1.McpCatalogService/SetCatalogMode", // D261: a lapsed org can still weaken or turn off the mode
	} {
		if c := procedureClasses[p]; c != entitlements.ClassSafety {
			t.Errorf("%s is %s, want safety", p, c)
		}
		if !entitlements.Allows(entitlements.StatusLapsed, procedureClass(p)) {
			t.Errorf("%s is refused on a lapsed plan", p)
		}
	}
}
