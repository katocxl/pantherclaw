// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// tenantTables are the org tables, from the catalog: every table under the
// tenant_isolation policy.
func tenantTables(t *testing.T, d *dbtest.DB) []string {
	t.Helper()
	p := d.Pool(t, d.Migrator)
	rows, err := p.Pgx().Query(context.Background(), `SELECT tablename FROM pg_policies
		WHERE schemaname = 'pc' AND policyname = 'tenant_isolation' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 200 {
		t.Fatalf("only %d org tables found", len(names))
	}
	return names
}

// TestHR391_DeleterRoleOnlyDeletesOrgRows: pc_deleter is LOGIN, NOINHERIT
// and never BYPASSRLS; it may SELECT and DELETE every org table but the
// platform's deletion records, may change only the tombstone columns of
// pc.orgs, and nothing else: no INSERT or UPDATE anywhere, no global
// table, no deletion record. Without app.org_id it sees and deletes
// nothing (RLS).
func TestHR391_DeleterRoleOnlyDeletesOrgRows(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	var super, createDB, createRole, repl, bypass, inherit, login bool
	d.AdminQueryRow(t, `SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit, rolcanlogin
		FROM pg_roles WHERE rolname = 'pc_deleter'`, nil, &super, &createDB, &createRole, &repl, &bypass, &inherit, &login)
	if super || createDB || createRole || repl || bypass || inherit || !login {
		t.Fatalf("pc_deleter attributes: super=%v createdb=%v createrole=%v replication=%v bypassrls=%v inherit=%v login=%v",
			super, createDB, createRole, repl, bypass, inherit, login)
	}
	for _, tb := range tenantTables(t, d) {
		var sel, del, ins, upd, trunc bool
		d.AdminQueryRow(t, `SELECT has_table_privilege('pc_deleter', $1, 'SELECT'), has_table_privilege('pc_deleter', $1, 'DELETE'),
			has_table_privilege('pc_deleter', $1, 'INSERT'), has_table_privilege('pc_deleter', $1, 'UPDATE'),
			has_table_privilege('pc_deleter', $1, 'TRUNCATE')`, []any{"pc." + tb}, &sel, &del, &ins, &upd, &trunc)
		switch tb {
		case "deletion_records":
			if sel || del || ins || upd || trunc {
				t.Errorf("%s: pc_deleter has a privilege on the platform's deletion records", tb)
			}
		case "orgs":
			if !sel || del || ins || trunc {
				t.Errorf("%s: select=%v delete=%v insert=%v truncate=%v, want select only (and the tombstone columns)", tb, sel, del, ins, trunc)
			}
		default:
			if !sel || !del || ins || upd || trunc {
				t.Errorf("%s: select=%v delete=%v insert=%v update=%v truncate=%v, want select and delete only",
					tb, sel, del, ins, upd, trunc)
			}
		}
	}
	for _, col := range []string{"id", "state", "deleted_at", "created_at"} {
		var upd bool
		d.AdminQueryRow(t, "SELECT has_column_privilege('pc_deleter', 'pc.orgs', $1, 'UPDATE')", []any{col}, &upd)
		if upd {
			t.Errorf("pc_deleter may update orgs.%s", col)
		}
	}
	for _, g := range globalTables {
		var has bool
		d.AdminQueryRow(t, `SELECT has_table_privilege('pc_deleter', $1, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE')`,
			[]any{"pc." + g}, &has)
		if has {
			t.Errorf("pc_deleter has a privilege on the global table %s", g)
		}
	}

	app := d.AppPool(t)
	org := createOrg(t, app, "a")
	del := d.Pool(t, d.Deleter)
	// No tenant setting: RLS shows nothing, so nothing is deleted.
	tag, err := del.Pgx().Exec(ctx, "DELETE FROM pc.org_containment")
	if err != nil || tag.RowsAffected() != 0 {
		t.Fatalf("delete without app.org_id: %v rows, err %v", tag.RowsAffected(), err)
	}
	err = del.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.org_containment (org_id) VALUES ($1)", org)
		return err
	})
	if !db.IsPermissionDenied(err) {
		t.Errorf("pc_deleter inserted: %v", err)
	}
}

// TestHR392_DeletedOrgStaysDeleted: once DELETED, an org never becomes
// anything else, its deletion time is set by the database and never moves.
func TestHR392_DeletedOrgStaysDeleted(t *testing.T) {
	d := dbtest.New(t)
	app := d.AppPool(t)
	ctx := context.Background()
	org := createOrg(t, app, "a")
	err := app.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.orgs SET state = 'DELETED' WHERE id = $1", org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var set bool
	d.AdminQueryRow(t, "SELECT deleted_at IS NOT NULL FROM pc.orgs WHERE id = $1", []any{org}, &set)
	if !set {
		t.Fatal("deleted_at not set")
	}
	for _, stmt := range []string{
		"UPDATE pc.orgs SET state = 'ACTIVE' WHERE id = $1",
		"UPDATE pc.orgs SET deleted_at = now() - interval '1 day' WHERE id = $1",
	} {
		err := app.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, stmt, org)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "23514") {
			t.Errorf("%s: err = %v, want refused", stmt, err)
		}
	}
	// The tombstone: the deleter scrubs the name, slug and creating account.
	err = d.Pool(t, d.Deleter).InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.orgs SET name = 'deleted', slug = NULL, created_by_account = NULL, updated_at = now() WHERE id = $1", org)
		return err
	})
	if err != nil {
		t.Fatalf("tombstone: %v", err)
	}
}
