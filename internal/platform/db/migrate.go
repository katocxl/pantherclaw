// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/katocxl/pantherclaw/migrations"
)

// MigrationResult describes one applied migration.
type MigrationResult struct {
	Version int64
	Source  string
}

// Migrate applies all pending migrations as pc_migrator (c.User must be the
// migrator role). Migrations are embedded in the binary. At the end it
// records the applied version in pc.schema_info (G0 M13 D19).
func Migrate(ctx context.Context, c Config) ([]MigrationResult, error) {
	return migrateFS(ctx, c, migrations.FS)
}

func migrateFS(ctx context.Context, c Config, fsys fs.FS) ([]MigrationResult, error) {
	if c.User != RoleMigrator {
		return nil, fmt.Errorf("db: migrations must run as %s, not %q", RoleMigrator, c.User)
	}
	sqlDB, err := openSQL(c)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sqlDB.Close() }()
	p, err := newProvider(sqlDB, fsys)
	if err != nil {
		return nil, err
	}
	res, err := p.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("db: migrate up: %w", err)
	}
	v, err := p.GetDBVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("db: migrate up: %w", err)
	}
	if err := recordSchemaVersion(ctx, sqlDB, v); err != nil {
		return nil, err
	}
	out := make([]MigrationResult, 0, len(res))
	for _, r := range res {
		out = append(out, MigrationResult{Version: r.Source.Version, Source: r.Source.Path})
	}
	return out, nil
}

// MigrationVersion returns the current schema version.
func MigrationVersion(ctx context.Context, c Config) (int64, error) {
	sqlDB, err := openSQL(c)
	if err != nil {
		return 0, err
	}
	defer func() { _ = sqlDB.Close() }()
	p, err := newProvider(sqlDB, migrations.FS)
	if err != nil {
		return 0, err
	}
	return p.GetDBVersion(ctx)
}

// newProvider combines the embedded SQL files with the Go-defined (River)
// migrations into one goose history.
func newProvider(sqlDB *sql.DB, fsys fs.FS) (*goose.Provider, error) {
	gm, err := migrations.Go()
	if err != nil {
		return nil, fmt.Errorf("db: migrations: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys, goose.WithGoMigrations(gm...))
	if err != nil {
		return nil, fmt.Errorf("db: migrations: %w", err)
	}
	return p, nil
}

func openSQL(c Config) (*sql.DB, error) {
	pc, err := c.poolConfig()
	if err != nil {
		return nil, err
	}
	// Migrations need neither the app-role check nor pooling hooks.
	pc.ConnConfig.RuntimeParams["statement_timeout"] = "600000"
	pc.ConnConfig.RuntimeParams["lock_timeout"] = ms(c.LockTimeout)
	return stdlib.OpenDB(*pc.ConnConfig), nil
}
