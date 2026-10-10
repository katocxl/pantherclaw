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

// TestHR198_EvidenceAdminNeedsItsHumanOnlyPermissions: retention and holds
// need evidence.retention.manage, capture profiles evidence.capture.manage
// and reading a capture evidence.read_restricted (HR-199), all human only;
// the Org Admin holds none of them, and the Auditor only the read (T-043).
func TestHR198_EvidenceAdminNeedsItsHumanOnlyPermissions(t *testing.T) {
	want := map[td.Permission]int{td.PermEvidenceRetentionManage: 5, td.PermEvidenceCaptureManage: 3, td.PermEvidenceReadRestricted: 1}
	got := map[td.Permission]int{}
	for proc, perm := range evidenceAdminProcedures {
		got[perm]++
		if procedurePermissions[proc] != perm {
			t.Errorf("%s: %q", proc, perm)
		}
	}
	if !maps.Equal(got, want) {
		t.Fatalf("procedures by permission %v, want %v (%v)", got, want, slices.Collect(maps.Keys(evidenceAdminProcedures)))
	}
	for p := range want {
		if !p.HumanOnly() {
			t.Errorf("%s must be human only", p)
		}
		if r, ok := td.LookupRole(td.RoleOrgAdmin); !ok || r.Has(p) {
			t.Errorf("the Org Admin holds %s", p)
		}
	}
	if r, ok := td.LookupRole(td.RoleAuditor); !ok || r.Has(td.PermEvidenceRetentionManage) || r.Has(td.PermEvidenceCaptureManage) ||
		!r.Has(td.PermEvidenceReadRestricted) {
		t.Error("the Auditor reads captures and neither configures retention nor capture")
	}
}
