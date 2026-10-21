// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package db_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR370_SchemaInfoRecordsTheAppliedVersion: `migrate up` records the
// applied version in pc.schema_info; the server role reads it there and
// sees the schema as current, and a recorded version above or below the
// binary's reads as newer or pending.
func TestHR370_SchemaInfoRecordsTheAppliedVersion(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	latest, err := db.LatestMigration()
	if err != nil {
		t.Fatal(err)
	}
	goose, err := db.MigrationVersion(ctx, d.Migrator)
	if err != nil {
		t.Fatal(err)
	}
	app := d.AppPool(t)
	v, ok, err := app.SchemaVersion(ctx)
	if err != nil || !ok || v != goose || v != latest {
		t.Fatalf("schema_info = %d (%v, %v), want goose's %d = latest %d", v, ok, err, goose, latest)
	}
	if st, err := app.CheckSchema(ctx); err != nil || st != db.SchemaCurrent {
		t.Fatalf("CheckSchema = %v, %v, want current", st, err)
	}
	// A re-run that applies nothing keeps the version.
	if _, err := db.Migrate(ctx, d.Migrator); err != nil {
		t.Fatal(err)
	}
	if v2, _, _ := app.SchemaVersion(ctx); v2 != v {
		t.Fatalf("version after a no-op migrate = %d, want %d", v2, v)
	}
	for want, set := range map[db.SchemaStatus]int64{db.SchemaNewer: latest + 1, db.SchemaPending: latest - 1} {
		d.AdminExec(t, "UPDATE pc.schema_info SET version = $1", set)
		if st, err := app.CheckSchema(ctx); err != nil || st != want {
			t.Errorf("recorded %d: CheckSchema = %v, %v, want %v", set, st, err, want)
		}
	}
	d.AdminExec(t, "DELETE FROM pc.schema_info")
	if st, err := app.CheckSchema(ctx); err != nil || st != db.SchemaPending {
		t.Errorf("no row: CheckSchema = %v, %v, want pending", st, err)
	}
	// migrate up writes it again.
	if _, err := db.Migrate(ctx, d.Migrator); err != nil {
		t.Fatal(err)
	}
	if st, err := app.CheckSchema(ctx); err != nil || st != db.SchemaCurrent {
		t.Errorf("after migrate up: CheckSchema = %v, %v, want current", st, err)
	}
}

// TestHR370_AppReadsSchemaInfoButNeitherWritesItNorReadsGoose: pc_app may
// only read pc.schema_info; goose's own table stays closed to it (D19).
func TestHR370_AppReadsSchemaInfoButNeitherWritesItNorReadsGoose(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	p := d.AppPool(t)
	org := ids.New[ids.Org]()
	denied := map[string]string{
		"insert":       "INSERT INTO pc.schema_info (id, version, applied_at) VALUES (1, 1, now()) ON CONFLICT DO NOTHING",
		"update":       "UPDATE pc.schema_info SET version = version + 1",
		"delete":       "DELETE FROM pc.schema_info",
		"truncate":     "TRUNCATE pc.schema_info",
		"goose select": "SELECT * FROM pc.goose_db_version",
		"goose update": "UPDATE pc.goose_db_version SET is_applied = false",
	}
	for name, stmt := range denied {
		err := p.InGlobalTx(ctx, db.GlobalHealth, func(ctx context.Context, tx db.GlobalTx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		if !db.IsPermissionDenied(err) {
			t.Errorf("global %s: err = %v, want insufficient_privilege", name, err)
		}
		err = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		if !db.IsPermissionDenied(err) {
			t.Errorf("tenant %s: err = %v, want insufficient_privilege", name, err)
		}
	}
	if _, ok, err := p.SchemaVersion(ctx); err != nil || !ok {
		t.Fatalf("pc_app read of schema_info = %v, %v", ok, err)
	}
}
