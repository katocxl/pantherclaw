// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR589_ScannerReachesOnlySubmitScanFindings walks every procedure the
// server serves: besides what any signed-in caller reaches, a Scanner gets
// past the interceptor on SubmitScanFindings and on the three org.read
// procedures, exactly. A new org.read procedure fails this test on purpose:
// it would reach a key taken from a laptop.
// Covers: F887
func TestHR589_ScannerReachesOnlySubmitScanFindings(t *testing.T) {
	scanner, ok := td.LookupRole(td.RoleScanner)
	if !ok {
		t.Fatal("no Scanner role")
	}
	want := []string{
		pantherclawv1connect.AgentServiceSubmitScanFindingsProcedure,
		pantherclawv1connect.ModelServiceGetModelDraftProcedure,
		pantherclawv1connect.ModelServiceGetModelSettingsProcedure,
		pantherclawv1connect.TenancyServiceGetOrgProcedure,
	}
	var reached []string
	for proc, perm := range procedurePermissions {
		if perm == td.PermPublic || perm == td.PermAuthenticated {
			continue
		}
		if alt, ok := m24AlternatePermissions[proc]; scanner.Has(perm) || (ok && scanner.Has(alt)) {
			reached = append(reached, proc)
		}
	}
	slices.Sort(reached)
	if !slices.Equal(reached, want) {
		t.Errorf("a Scanner reaches %v, want %v", reached, want)
	}
}

// TestHR589_OnlyTheScanProcedureHasAnAlternate: the second permission is one
// entry, and the procedure's declared permission stays as it was.
// Covers: F887
func TestHR589_OnlyTheScanProcedureHasAnAlternate(t *testing.T) {
	proc := pantherclawv1connect.AgentServiceSubmitScanFindingsProcedure
	if len(m24AlternatePermissions) != 1 || m24AlternatePermissions[proc] != td.PermAgentScanSubmit {
		t.Fatalf("alternates: %v", m24AlternatePermissions)
	}
	if procedurePermissions[proc] != td.PermAgentManage {
		t.Errorf("declared permission: %s", procedurePermissions[proc])
	}
	if gatewayListenerPermissions()[proc] != td.PermGatewayScanSubmit {
		t.Error("the gateway listener's permission moved")
	}
}

// TestD246_DeviceLimitsAreConfig: the defaults, and a limit below 1 refused.
// Covers: F885
func TestD246_DeviceLimitsAreConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Limits.Scan.NewDeviceScopesPerKeyPerHour != 1000 || c.Limits.Scan.OpenDeviceScopesPerOrg != 20000 {
		t.Fatalf("defaults: %+v", c.Limits.Scan)
	}
	if errs := c.validateLimits(); len(errs) != 0 {
		t.Fatalf("defaults refused: %v", errs)
	}
	c.Limits.Scan.OpenDeviceScopesPerOrg = 0
	if errs := c.validateLimits(); len(errs) != 1 {
		t.Fatalf("zero limit: %v", errs)
	}
}
