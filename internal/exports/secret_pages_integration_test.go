// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exports

import (
	"errors"
	"testing"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestThePageUseCasesNeedAFreshStepUpAndThePermission (G0 M22 D57): the
// server page's use cases refuse a missing or stale step-up and write
// nothing, refuse a stepped-up person without siem.manage, and audit what
// they do; the credential is never in the audit.
func TestThePageUseCasesNeedAFreshStepUpAndThePermission(t *testing.T) {
	f := newFixture(t, Config{})
	admin := f.as(td.KindUser, td.RoleSecurityAdmin)
	const token = "token-not-to-be-seen-1234"
	in := NewDestination{
		Name: "vault", Target: put("https://s.example.net/in"), DataClasses: []string{ClassOrgExports}, Credential: Credential{BearerToken: token},
	}
	fresh := stepup.StepUp{Credential: f.key, At: time.Now()}
	for name, su := range map[string]stepup.StepUp{
		"none":  {},
		"stale": {Credential: f.key, At: time.Now().Add(-6 * time.Minute)},
	} {
		if _, err := f.svc.CreateOnPage(admin, in, su); !errors.Is(err, stepup.ErrStepUp) {
			t.Fatalf("create, %s step-up: %v", name, err)
		}
	}
	count := func(sql string) int {
		t.Helper()
		var n int
		f.d.AdminQueryRow(t, sql, []any{f.org}, &n)
		return n
	}
	if n := count("SELECT count(*)::int FROM pc.export_destinations WHERE org_id = $1"); n != 0 {
		t.Fatalf("a refused create stored %d destinations", n)
	}
	if _, err := f.svc.CreateOnPage(f.as(td.KindUser, td.RoleAuditor), in, fresh); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("an auditor: %v", err)
	}

	d, err := f.svc.CreateOnPage(admin, in, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReplaceCredentialOnPage(admin, d.ID, Credential{BearerToken: token + "2"}, stepup.StepUp{}); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("replace with no step-up: %v", err)
	}
	if _, err := f.svc.ReplaceCredentialOnPage(admin, d.ID, Credential{BearerToken: token + "2"}, fresh); err != nil {
		t.Fatal(err)
	}
	if n := count("SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE 'audit.export.destination_%'"); n != 2 {
		t.Fatalf("audits: %d, want the create and the replacement", n)
	}
	if n := count("SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND position('" + token + "'::bytea IN body) > 0"); n != 0 {
		t.Fatal("the credential reached the audit")
	}
}
