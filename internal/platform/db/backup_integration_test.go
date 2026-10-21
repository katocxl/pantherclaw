// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR378_BackupRoleOnlyReadsEveryOrg: `db bootstrap
// --backup-password-file` gives pc_backup exactly LOGIN, NOINHERIT and
// BYPASSRLS; it reads every org's rows (and the migration bookkeeping, as
// data) and every table created later, and can write, create or execute
// nothing.
func TestHR378_BackupRoleOnlyReadsEveryOrg(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	pw := []byte("backup-role-test-password-0123456789")
	d.AdminDo(t, func(c *pgx.Conn) error {
		if err := db.BootstrapBackupRole(ctx, c, pclog.NewSecret(pw)); err != nil {
			return err
		}
		return db.BootstrapDatabase(ctx, c)
	})
	var super, createDB, createRole, repl, bypass, inherit, login bool
	d.AdminQueryRow(t, `SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit, rolcanlogin
		FROM pg_roles WHERE rolname = 'pc_backup'`, nil, &super, &createDB, &createRole, &repl, &bypass, &inherit, &login)
	if super || createDB || createRole || repl || !bypass || inherit || !login {
		t.Fatalf("pc_backup attributes: super=%v createdb=%v createrole=%v replication=%v bypassrls=%v inherit=%v login=%v",
			super, createDB, createRole, repl, bypass, inherit, login)
	}
	var member int
	d.AdminQueryRow(t, "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = 'pc_backup'", nil, &member)
	if member != 0 {
		t.Fatalf("pc_backup is a member of %d roles", member)
	}

	orgA, orgB := ids.New[ids.Org](), ids.New[ids.Org]()
	for _, o := range []ids.OrgID{orgA, orgB} {
		d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'o')", o)
		d.AdminExec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1)", o)
	}
	// A table the migrator creates after bootstrap is readable too.
	d.AdminExec(t, "SET ROLE pc_migrator; CREATE TABLE pc.backup_probe (id int); INSERT INTO pc.backup_probe VALUES (1); RESET ROLE")

	c := d.ConnectAs(t, db.RoleBackup, pw)
	var n int
	if err := c.QueryRow(ctx, "SELECT count(*) FROM pc.org_containment WHERE org_id = ANY($1)", []ids.OrgID{orgA, orgB}).Scan(&n); err != nil || n != 2 {
		t.Fatalf("cross-org read = %d, %v, want both orgs", n, err)
	}
	for _, q := range []string{
		"SELECT count(*) FROM pc.goose_db_version",
		"SELECT count(*) FROM pc.schema_info",
		"SELECT count(*) FROM pc.ledger_entries",
		"SELECT count(*) FROM pc.keys",
		"SELECT count(*) FROM pc.backup_probe",
	} {
		if err := c.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	denied := map[string]string{
		"insert":         "INSERT INTO pc.orgs (id, name) VALUES ('" + ids.New[ids.Org]().String() + "', 'x')",
		"update":         "UPDATE pc.org_containment SET epoch = epoch + 1",
		"delete":         "DELETE FROM pc.org_containment",
		"truncate":       "TRUNCATE pc.backup_probe",
		"create in pc":   "CREATE TABLE pc.evil (id int)",
		"create public":  "CREATE TABLE public.evil (id int)",
		"lister":         "SELECT * FROM pc.cross_org_list('orgs', 10)",
		"set role":       "SET ROLE pc_migrator",
		"goose write":    "DELETE FROM pc.goose_db_version",
		"sequence write": "SELECT setval(c.oid, 1) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'pc' AND c.relkind = 'S' LIMIT 1",
	}
	for name, stmt := range denied {
		_, err := c.Exec(ctx, stmt)
		if !db.IsPermissionDenied(err) {
			t.Errorf("%s: %q: err = %v, want insufficient_privilege", name, stmt, err)
		}
	}
}
