// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package db_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// globalTables are the only tables in schema pc without tenant RLS. Adding a
// table here requires a G0/G1 justification (HR-053).
var globalTables = []string{
	"anchors",              // the anchored global roots: blinded leaves only, no tenant data (G0 M7, HR-195)
	"cross_org_list_audit", // audit of the cross-org lister; no pc_app access
	"goose_db_version",     // migration bookkeeping; no pc_app access
	"licence_state",        // single global row: the installed licence (no tenant data)
}

func createOrg(t *testing.T, p *db.Pool, name string) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", tx.OrgID(), name)
		return err
	})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	return org
}

func countOrgs(ctx context.Context, t *testing.T, q db.DBTX) int {
	t.Helper()
	var n int
	if err := q.QueryRow(ctx, "SELECT count(*) FROM pc.orgs").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHR052_MissingTenantSettingMatchesNothing(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	createOrg(t, p, "a")
	createOrg(t, p, "b")
	ctx := context.Background()
	if n := countOrgs(ctx, t, p.Pgx()); n != 0 {
		t.Fatalf("pc_app without tenant context sees %d orgs, want 0", n)
	}
	err := p.InGlobalTx(context.Background(), db.GlobalHealth, func(ctx context.Context, tx db.GlobalTx) error {
		if n := countOrgs(ctx, t, tx); n != 0 {
			t.Errorf("global tx sees %d orgs, want 0", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestT003_CrossTenantReadWriteIsolation(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a := createOrg(t, p, "a")
	b := createOrg(t, p, "b")
	ctx := context.Background()
	err := p.InTenantTx(ctx, a, func(ctx context.Context, tx db.TenantTx) error {
		if n := countOrgs(ctx, t, tx); n != 1 {
			t.Errorf("org a sees %d orgs, want 1", n)
		}
		var name string
		err := tx.QueryRow(ctx, "SELECT name FROM pc.orgs WHERE id = $1", b).Scan(&name)
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("org a read org b: %q, %v", name, err)
		}
		tag, err := tx.Exec(ctx, "UPDATE pc.orgs SET name = 'pwned' WHERE id = $1", b)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("org a updated org b: %v rows, %v", tag.RowsAffected(), err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Writing a row for another tenant fails the WITH CHECK clause.
	err = p.InTenantTx(ctx, a, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'x')", ids.New[ids.Org]())
		return err
	})
	if !db.IsPermissionDenied(err) {
		t.Fatalf("insert of a foreign tenant row: err = %v, want RLS violation", err)
	}
	// Moving one's own row to another tenant id also fails.
	err = p.InTenantTx(ctx, a, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.orgs SET id = $1 WHERE id = $2", b, a)
		return err
	})
	if err == nil {
		t.Fatal("re-keying a row to another tenant succeeded")
	}
}

func TestHR051_ZeroOrgIsRejected(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	err := p.InTenantTx(context.Background(), ids.OrgID{}, func(context.Context, db.TenantTx) error {
		t.Fatal("callback ran without a tenant")
		return nil
	})
	if !errors.Is(err, db.ErrNoTenant) {
		t.Fatalf("err = %v, want ErrNoTenant", err)
	}
	if err := p.InGlobalTx(context.Background(), "anything", func(context.Context, db.GlobalTx) error { return nil }); err == nil {
		t.Fatal("unregistered global purpose accepted")
	}
}

func TestHR052_SessionLevelTenantIsResetOnRelease(t *testing.T) {
	d := dbtest.New(t)
	c := d.App
	c.MaxConns = 1
	p := d.Pool(t, c)
	a := createOrg(t, p, "a")
	ctx := context.Background()
	conn, err := p.Pgx().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a bug that sets the tenant at session level (is_local=false).
	if _, err := conn.Exec(ctx, "SELECT set_config('app.org_id', $1, false)", a.String()); err != nil {
		t.Fatal(err)
	}
	if n := countOrgs(ctx, t, conn); n != 1 {
		t.Fatalf("precondition: session-level tenant should see 1 org, saw %d", n)
	}
	conn.Release()
	// The single pooled connection comes back after AfterRelease ran RESET ALL.
	if n := countOrgs(ctx, t, p.Pgx()); n != 0 {
		t.Fatalf("tenant setting leaked through the pool: %d orgs visible", n)
	}
}

func TestHR057_TimeoutsOnEveryConnectionSurviveResetAll(t *testing.T) {
	d := dbtest.New(t)
	c := d.App
	c.MaxConns = 1
	p := d.Pool(t, c)
	ctx := context.Background()
	show := func() (string, string, string) {
		var s, l, i string
		err := p.Pgx().QueryRow(ctx, `SELECT current_setting('statement_timeout'), current_setting('lock_timeout'),
			current_setting('idle_in_transaction_session_timeout')`).Scan(&s, &l, &i)
		if err != nil {
			t.Fatal(err)
		}
		return s, l, i
	}
	s, l, i := show()
	if s != "5s" || l != "2s" || i != "10s" {
		t.Fatalf("timeouts = %s/%s/%s, want 5s/2s/10s", s, l, i)
	}
	if _, err := p.Pgx().Exec(ctx, "SET statement_timeout = 0"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Pgx().Exec(ctx, "RESET ALL"); err != nil {
		t.Fatal(err)
	}
	if s, _, _ := show(); s != "5s" {
		t.Fatalf("statement_timeout after RESET ALL = %s, want 5s", s)
	}
	// A statement that exceeds the timeout is canceled.
	short := d.App
	short.StatementTimeout = 50_000_000 // 50ms
	sp := d.Pool(t, short)
	if _, err := sp.Pgx().Exec(ctx, "SELECT pg_sleep(1)"); err == nil || !strings.Contains(err.Error(), "statement timeout") {
		t.Fatalf("pg_sleep(1) with 50ms timeout: %v", err)
	}
}

func TestHR055_AppRoleCannotEscalate(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a := createOrg(t, p, "a")
	ctx := context.Background()
	denied := map[string]string{
		"truncate":       "TRUNCATE pc.orgs",
		"delete":         "DELETE FROM pc.orgs",
		"ddl":            "CREATE TABLE pc.evil (id int)",
		"ddl public":     "CREATE TABLE public.evil (id int)",
		"alter":          "ALTER TABLE pc.orgs NO FORCE ROW LEVEL SECURITY",
		"copy to file":   "COPY pc.orgs TO '/tmp/orgs.csv'",
		"temp table":     "CREATE TEMP TABLE t (id int)",
		"lister audit":   "SELECT * FROM pc.cross_org_list_audit",
		"migrations":     "SELECT * FROM pc.goose_db_version",
		"set role":       "SET ROLE pc_lister",
		"bypass rls off": "SET row_security = off; SELECT count(*) FROM pc.orgs",
	}
	for name, stmt := range denied {
		err := p.InTenantTx(ctx, a, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		if !db.IsPermissionDenied(err) {
			t.Errorf("%s: %q: err = %v, want insufficient_privilege (42501)", name, stmt, err)
		}
	}
	var super, bypass, readFiles, writeFiles, exec bool
	err := p.Pgx().QueryRow(ctx, `
		SELECT r.rolsuper, r.rolbypassrls,
		       pg_has_role('pc_app', 'pg_read_server_files', 'MEMBER'),
		       pg_has_role('pc_app', 'pg_write_server_files', 'MEMBER'),
		       pg_has_role('pc_app', 'pg_execute_server_program', 'MEMBER')
		FROM pg_roles r WHERE r.rolname = 'pc_app'`).Scan(&super, &bypass, &readFiles, &writeFiles, &exec)
	if err != nil {
		t.Fatal(err)
	}
	if super || bypass || readFiles || writeFiles || exec {
		t.Fatalf("pc_app privileges: super=%v bypassrls=%v read=%v write=%v exec=%v", super, bypass, readFiles, writeFiles, exec)
	}
	var hasTruncate bool
	if err := p.Pgx().QueryRow(ctx, `
		SELECT bool_or(has_table_privilege('pc_app', c.oid, 'TRUNCATE'))
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'pc' AND c.relkind IN ('r', 'p')`).Scan(&hasTruncate); err != nil {
		t.Fatal(err)
	}
	if hasTruncate {
		t.Fatal("pc_app has TRUNCATE on a table in schema pc")
	}
}

func TestHR055_AppPoolRefusesPrivilegedRole(t *testing.T) {
	d := dbtest.New(t)
	c := d.AdminConfig()
	c.RequireUnprivileged = true
	_, err := db.Open(context.Background(), c)
	if !errors.Is(err, db.ErrSessionMisconfigured) {
		t.Fatalf("superuser app pool: err = %v, want ErrSessionMisconfigured", err)
	}
}

// TestHR053_EveryTenantTableIsIsolated is the generated table-list check
// (BUILD_GUIDE §3.3): it inspects the catalog, so new tables are covered
// without editing the test.
func TestHR053_EveryTenantTableIsIsolated(t *testing.T) {
	d := dbtest.New(t)
	p := d.Pool(t, d.Migrator)
	ctx := context.Background()
	rows, err := p.Pgx().Query(ctx, `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'pc' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	type table struct {
		name          string
		rls, forceRLS bool
	}
	tables, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (table, error) {
		var tb table
		err := r.Scan(&tb.name, &tb.rls, &tb.forceRLS)
		return tb, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) == 0 {
		t.Fatal("no tables found in schema pc")
	}
	const policyExpr = "NULLIF(current_setting('app.org_id'::text, true), ''::text))::uuid"
	for _, tb := range tables {
		if slices.Contains(globalTables, tb.name) || strings.HasPrefix(tb.name, "river_") {
			continue
		}
		t.Run(tb.name, func(t *testing.T) {
			if !tb.rls || !tb.forceRLS {
				t.Errorf("RLS enabled=%v forced=%v, want both (HR-053)", tb.rls, tb.forceRLS)
			}
			keyCol := "org_id"
			if tb.name == "orgs" {
				keyCol = "id"
			}
			var policies []string
			prow, err := p.Pgx().Query(ctx, `SELECT coalesce(qual, '') || ' | ' || coalesce(with_check, '')
				FROM pg_policies WHERE schemaname = 'pc' AND tablename = $1`, tb.name)
			if err != nil {
				t.Fatal(err)
			}
			policies, err = pgx.CollectRows(prow, pgx.RowTo[string])
			if err != nil {
				t.Fatal(err)
			}
			if len(policies) != 1 || !strings.Contains(policies[0], keyCol+" = ( SELECT (") ||
				strings.Count(policies[0], policyExpr) != 2 {
				t.Errorf("policies = %q, want one USING + WITH CHECK on %s with the standard expression (HR-052)", policies, keyCol)
			}
		})
	}
	checkSecurityDefinersAndViews(ctx, t, p)
}

// TestHR050_TenantKeysAndForeignKeysLeadWithOrgID checks, from the catalog,
// that every unique index (including primary keys) and every foreign key of
// every tenant table starts with org_id, so uniqueness and references are
// always scoped to one tenant (no cross-tenant existence oracles).
func TestHR050_TenantKeysAndForeignKeysLeadWithOrgID(t *testing.T) {
	d := dbtest.New(t)
	p := d.Pool(t, d.Migrator)
	ctx := context.Background()
	rows, err := p.Pgx().Query(ctx, `
		SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'pc' AND c.relkind IN ('r', 'p') AND NOT c.relispartition ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if slices.Contains(globalTables, name) || strings.HasPrefix(name, "river_") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			keyCol := "org_id"
			if name == "orgs" {
				keyCol = "id"
			}
			// Every unique index (incl. the primary key) starts with the tenant column (HR-050).
			urows, err := p.Pgx().Query(ctx, `
				SELECT i.indexrelid::regclass::text, a.attname
				FROM pg_index i
				JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
				WHERE i.indrelid = ('pc.' || quote_ident($1))::regclass AND i.indisunique`, name)
			if err != nil {
				t.Fatal(err)
			}
			type idx struct{ name, first string }
			idxs, err := pgx.CollectRows(urows, func(r pgx.CollectableRow) (idx, error) {
				var x idx
				err := r.Scan(&x.name, &x.first)
				return x, err
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, x := range idxs {
				if x.first != keyCol {
					t.Errorf("unique index %s starts with %s, want %s (HR-050)", x.name, x.first, keyCol)
				}
			}
			// Every foreign key includes org_id as its first column (HR-050).
			frows, err := p.Pgx().Query(ctx, `
				SELECT con.conname, a.attname
				FROM pg_constraint con
				JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = con.conkey[1]
				WHERE con.conrelid = ('pc.' || quote_ident($1))::regclass AND con.contype = 'f'`, name)
			if err != nil {
				t.Fatal(err)
			}
			fks, err := pgx.CollectRows(frows, func(r pgx.CollectableRow) (idx, error) {
				var x idx
				err := r.Scan(&x.name, &x.first)
				return x, err
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, fk := range fks {
				if fk.first != "org_id" {
					t.Errorf("foreign key %s starts with %s, want composite (org_id, …) (HR-050)", fk.name, fk.first)
				}
			}
		})
	}
}

// checkSecurityDefinersAndViews: exactly one SECURITY DEFINER function
// exists, and every view is security_invoker (HR-053).
func checkSecurityDefinersAndViews(ctx context.Context, t *testing.T, p *db.Pool) {
	t.Helper()
	var definers []string
	drows, err := p.Pgx().Query(ctx, `SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'pc' AND p.prosecdef ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	definers, err = pgx.CollectRows(drows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(definers, []string{"cross_org_list"}) {
		t.Errorf("SECURITY DEFINER functions = %v, want only cross_org_list (HR-053)", definers)
	}
	var badViews []string
	vrows, err := p.Pgx().Query(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'pc' AND c.relkind = 'v'
		  AND NOT coalesce(c.reloptions @> ARRAY['security_invoker=true'], false)`)
	if err != nil {
		t.Fatal(err)
	}
	badViews, err = pgx.CollectRows(vrows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(badViews) > 0 {
		t.Errorf("views without security_invoker: %v (HR-053)", badViews)
	}
}

func TestHR054_CrossOrgListerIsAuditedAndRestricted(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a := createOrg(t, p, "a")
	b := createOrg(t, p, "b")
	ctx := context.Background()
	refs, err := p.CrossOrgList(ctx, db.ListActiveOrgs, 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []ids.OrgID
	for _, r := range refs {
		got = append(got, r.Org)
	}
	for _, want := range []ids.OrgID{a, b, ids.PlatformOrg} {
		if !slices.Contains(got, want) {
			t.Errorf("lister result %v misses %v", got, want)
		}
	}
	if _, err := p.CrossOrgList(ctx, "orgs'; DROP TABLE pc.orgs; --", 10); err == nil {
		t.Error("unknown lister purpose accepted")
	}
	for _, n := range []int{0, -1, 10001} {
		if _, err := p.CrossOrgList(ctx, db.ListActiveOrgs, n); err == nil {
			t.Errorf("max_rows %d accepted", n)
		}
	}
	var audited int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.cross_org_list_audit WHERE purpose = 'orgs' AND caller = 'pc_app'", nil, &audited)
	if audited != 1 {
		t.Fatalf("audit rows for successful calls = %d, want 1", audited)
	}
}

func TestHR004_ConditionalTransitionHasOneWinner(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a := createOrg(t, p, "a")
	ctx := context.Background()
	var wins, lost atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			err := p.InTenantTx(ctx, a, func(ctx context.Context, tx db.TenantTx) error {
				return db.ExpectOneRow(tx.Exec(ctx,
					"UPDATE pc.orgs SET state = 'SUSPENDED', updated_at = now() WHERE id = $1 AND state = 'ACTIVE'", tx.OrgID()))
			})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, db.ErrLostRace):
				lost.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 || lost.Load() != 19 {
		t.Fatalf("wins=%d lost=%d, want exactly one winner", wins.Load(), lost.Load())
	}
}

func TestBootstrapAndMigrateAreGuarded(t *testing.T) {
	d := dbtest.New(t)
	if _, err := db.Migrate(context.Background(), d.App); err == nil {
		t.Fatal("migrations ran as pc_app")
	}
	v, err := db.MigrationVersion(context.Background(), d.Migrator)
	if err != nil || v < 1 {
		t.Fatalf("migration version = %d, %v", v, err)
	}
	// Re-running migrations is a no-op.
	res, err := db.Migrate(context.Background(), d.Migrator)
	if err != nil || len(res) != 0 {
		t.Fatalf("second migrate = %v, %v", res, err)
	}
}
