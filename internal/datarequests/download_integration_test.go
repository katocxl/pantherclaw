// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package datarequests

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// readyExport builds a READY export of org, asked for by a new org admin,
// and returns its id and a browser-session context of that admin.
func readyExport(t *testing.T, d *dbtest.DB, s *Service, org ids.OrgID) (ids.UUID, context.Context) {
	t.Helper()
	user, id := ids.NewV7(), ids.NewV7()
	d.AdminExec(t, "INSERT INTO pc.users(org_id,id,issuer,subject,email) VALUES($1,$2,'test',$3,'admin@example.com')", org, user, user.String())
	d.AdminExec(t, "INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by) VALUES($1,$2,'org_admin',$3,'ORG','system:test')", org, ids.NewV7(), user)
	d.AdminExec(t, "INSERT INTO pc.data_requests(org_id,id,kind,state,created_by,admin_accounts) VALUES($1,$2,'EXPORT','BUILDING',$3,'{}')", org, id, user)
	if err := s.Build(t.Context(), org, id); err != nil {
		t.Fatal(err)
	}
	return id, personCtx(org, user, td.RoleOrgAdmin)
}

func personCtx(org ids.OrgID, user ids.UUID, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject:    td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}}},
		Credential: tapp.CredBrowserSession, Session: ids.NewV7(),
	})
}

func downloads(t *testing.T, s *Service, org ids.OrgID) int {
	t.Helper()
	var n int
	if err := s.Pool.InTenantTx(t.Context(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.data.export_downloaded'", org).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestHR399_ExportPartsOnlyForTheOwnOrgsAdminBeforeExpiry: an export part
// is served to an org admin of the export's own org while the export is
// READY and unexpired, and every download is audited in the same
// transaction; another org's admin, a viewer and an expired export are
// refused, and a refused download writes no download audit (T-177; RT-069).
func TestHR399_ExportPartsOnlyForTheOwnOrgsAdminBeforeExpiry(t *testing.T) {
	d, s, org := setup(t)
	id, admin := readyExport(t, d, s, org)
	p, err := s.Download(admin, id, 1)
	if err != nil || len(p.Content) == 0 || len(p.Sha256) != 32 {
		t.Fatalf("own admin download: %v (%d bytes)", err, len(p.Content))
	}
	if n := downloads(t, s, org); n != 1 {
		t.Fatalf("%d download audits, want 1", n)
	}

	other := ids.New[ids.Org]()
	d.AdminExec(t, "INSERT INTO pc.orgs(id,name) VALUES($1,'other')", other)
	_, otherAdmin := readyExport(t, d, s, other)
	if _, err := s.Download(otherAdmin, id, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another org's admin: %v, want DATA_REQUEST_NOT_FOUND", err)
	}
	if _, err := s.Download(personCtx(org, ids.NewV7(), td.RoleViewer), id, 1); err == nil {
		t.Fatal("a viewer downloaded the export")
	}

	d.AdminExec(t, "UPDATE pc.data_requests SET expires_at = now() - interval '1 second' WHERE org_id = $1 AND id = $2", org, id)
	if _, err := s.Download(admin, id, 1); !errors.Is(err, ErrExportUnavailable) {
		t.Fatalf("expired export: %v, want EXPORT_UNAVAILABLE", err)
	}
	if n := downloads(t, s, org); n != 1 {
		t.Fatalf("%d download audits after refusals, want 1", n)
	}
}
