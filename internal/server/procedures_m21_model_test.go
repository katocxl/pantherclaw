// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR554_ModelReadsNeedMoreThanOrgRead: the interceptor asks policy.read
// to list drafts and audit.read to read usage (G0 M24 D95), and a role that
// holds neither, org.read included, gets past it on neither.
//
// Covers: F834
func TestHR554_ModelReadsNeedMoreThanOrgRead(t *testing.T) {
	want := map[string]td.Permission{
		pantherclawv1connect.ModelServiceListModelDraftsProcedure: td.PermPolicyRead,
		pantherclawv1connect.ModelServiceGetModelUsageProcedure:   td.PermAuditRead,
	}
	for proc, perm := range want {
		if got := procedurePermissions[proc]; got != perm {
			t.Errorf("%s needs %q, want %q", proc, got, perm)
		}
	}
	for _, name := range []td.RoleName{td.RoleScanner, td.RoleViewer} {
		role, ok := td.LookupRole(name)
		if !ok {
			t.Fatalf("no %s role", name)
		}
		if !role.Has(td.PermOrgRead) {
			t.Fatalf("%s no longer holds org.read: this test proves nothing", name)
		}
		for proc := range want {
			if role.Has(procedurePermissions[proc]) {
				t.Errorf("%s reaches %s", name, proc)
			}
		}
	}
}
