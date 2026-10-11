// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR198_RetentionRunsOnARoleOfItsOwn: the retention job never connects
// as the application's or the migrator's role, nor with pc_app's password
// file; the default is pc_retention, and an unset password file is allowed
// (nothing is removed, and the job reports it).
func TestHR198_RetentionRunsOnARoleOfItsOwn(t *testing.T) {
	c := DefaultConfig()
	c.DB.AppPasswordFile = "app.pw"
	if u := c.retentionUser(); u != db.RoleRetention {
		t.Fatalf("default retention user %q", u)
	}
	if errs := c.validateRetention(); len(errs) != 0 {
		t.Fatalf("defaults: %v", errs)
	}
	c.DB.RetentionPasswordFile = "retention.pw"
	if errs := c.validateRetention(); len(errs) != 0 {
		t.Fatalf("with a password file: %v", errs)
	}
	for _, u := range []string{db.RoleApp, db.RoleMigrator, "postgres"} {
		c := c
		c.DB.RetentionUser = u
		if errs := c.validateRetention(); len(errs) == 0 {
			t.Errorf("retention_user %q accepted", u)
		}
	}
	c.DB.RetentionPasswordFile = c.DB.AppPasswordFile
	if errs := c.validateRetention(); len(errs) == 0 {
		t.Error("pc_app's password file accepted for the retention role")
	}
}

// TestHR198_EvidenceAdminIsRetentionManageOnly: every EvidenceAdminService
// procedure needs evidence.retention.manage, a human-only permission that
// neither the Org Admin nor the Auditor holds (T-043).
func TestHR198_EvidenceAdminIsRetentionManageOnly(t *testing.T) {
	if len(evidenceAdminProcedures) != 5 {
		t.Fatalf("procedures %v", slices.Collect(maps.Keys(evidenceAdminProcedures)))
	}
	for proc, perm := range evidenceAdminProcedures {
		if perm != td.PermEvidenceRetentionManage || procedurePermissions[proc] != perm {
			t.Errorf("%s: %q", proc, perm)
		}
	}
	if !td.PermEvidenceRetentionManage.HumanOnly() {
		t.Fatal("evidence.retention.manage must be human only")
	}
	for _, name := range []td.RoleName{td.RoleOrgAdmin, td.RoleAuditor, td.RoleSecurityAdmin} {
		if r, ok := td.LookupRole(name); !ok || r.Has(td.PermEvidenceRetentionManage) {
			t.Errorf("%s holds evidence.retention.manage", name)
		}
	}
}
