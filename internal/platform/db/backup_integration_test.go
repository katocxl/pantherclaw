// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package db_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// backupFixture bootstraps pc_backup the way `db bootstrap
// --backup-password-file` does, adds two orgs and a table the migrator
// creates afterwards, and connects as pc_backup.
type backupFixture struct {
	d          *dbtest.DB
	conn       *pgx.Conn
	orgA, orgB ids.OrgID
}

func newBackupFixture(t *testing.T) backupFixture {
	t.Helper()
	d := dbtest.New(t)
	ctx := context.Background()
	pw := []byte("backup-role-test-password-0123456789")
	d.AdminDo(t, func(c *pgx.Conn) error {
		if err := db.BootstrapBackupRole(ctx, c, pclog.NewSecret(pw)); err != nil {
			return err
		}
		return db.BootstrapDatabase(ctx, c)
	})
	f := backupFixture{d: d, orgA: ids.New[ids.Org](), orgB: ids.New[ids.Org]()}
	for _, o := range []ids.OrgID{f.orgA, f.orgB} {
		d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'o')", o)
		d.AdminExec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1)", o)
	}
	// A table the migrator creates after bootstrap is readable too.
	d.AdminExec(t, "SET ROLE pc_migrator; CREATE TABLE pc.backup_probe (id int); INSERT INTO pc.backup_probe VALUES (1); RESET ROLE")
	f.conn = d.ConnectAs(t, db.RoleBackup, pw)
	return f
}

func (f backupFixture) denied(t *testing.T, stmts map[string]string) {
	t.Helper()
	for name, stmt := range stmts {
		_, err := f.conn.Exec(context.Background(), stmt)
		if !db.IsPermissionDenied(err) {
			t.Errorf("%s: %q: err = %v, want insufficient_privilege", name, stmt, err)
		}
	}
}

// TestHR378_BackupRoleOnlyReadsEveryOrg: `db bootstrap
// --backup-password-file` gives pc_backup exactly LOGIN, NOINHERIT and
// BYPASSRLS; it reads every org's rows (and the migration bookkeeping, as
// data) and every table created later, and can write, create or execute
// nothing.
func TestHR378_BackupRoleOnlyReadsEveryOrg(t *testing.T) {
	f := newBackupFixture(t)
	d, c, ctx := f.d, f.conn, context.Background()
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

	var n int
	if err := c.QueryRow(ctx, "SELECT count(*) FROM pc.org_containment WHERE org_id = ANY($1)", []ids.OrgID{f.orgA, f.orgB}).Scan(&n); err != nil || n != 2 {
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
	f.denied(t, map[string]string{
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
	})
}

// TestT172_StolenBackupCredentialCannotChangeAnything: a stolen pc_backup
// credential reads (that is what age encryption and bucket-scoped storage
// keys contain), but cannot alter, drop or grant anything, write files
// on the server, keep data in temporary tables, or run the lister; a dump
// works inside pg_dump's read-only snapshot transaction.
func TestT172_StolenBackupCredentialCannotChangeAnything(t *testing.T) {
	f := newBackupFixture(t)
	ctx := context.Background()
	f.denied(t, map[string]string{
		"alter table":    "ALTER TABLE pc.orgs ADD COLUMN evil int",
		"disable rls":    "ALTER TABLE pc.orgs NO FORCE ROW LEVEL SECURITY",
		"drop table":     "DROP TABLE pc.backup_probe",
		"create schema":  "CREATE SCHEMA evil",
		"temp table":     "CREATE TEMP TABLE evil (id int)",
		"copy to file":   "COPY pc.orgs TO '/tmp/pc_orgs.csv'",
		"copy from file": "COPY pc.backup_probe FROM '/tmp/pc_probe.csv'",
		"create role":    "CREATE ROLE evil",
		"function":       "CREATE FUNCTION pc.evil() RETURNS int LANGUAGE sql AS 'SELECT 1'",
	})
	// What pg_dump does: a read-only serializable snapshot and COPY TO STDOUT.
	tx, err := f.conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly, DeferrableMode: pgx.Deferrable})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var out bytes.Buffer
	if _, err := tx.Conn().PgConn().CopyTo(ctx, &out, "COPY pc.org_containment TO STDOUT"); err != nil {
		t.Fatalf("dump copy: %v", err)
	}
	if !strings.Contains(out.String(), f.orgA.String()) || !strings.Contains(out.String(), f.orgB.String()) {
		t.Errorf("dump lacks an org: %s", out.String())
	}
	if _, err := tx.Exec(ctx, "UPDATE pc.backup_probe SET id = 2"); err == nil {
		t.Error("a write succeeded in the dump transaction")
	}
}
