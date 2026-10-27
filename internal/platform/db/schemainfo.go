// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/katocxl/pantherclaw/migrations"
)

// LatestMigration returns the newest migration version embedded in the
// binary: the schema version this build expects (G0 M13 D3, HR-370).
var LatestMigration = sync.OnceValues(func() (int64, error) {
	return latestIn(migrations.FS)
})

func latestIn(fsys fs.FS) (int64, error) {
	var latest int64
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return 0, fmt.Errorf("db: migrations: %w", err)
	}
	for _, e := range entries {
		v, err := goose.NumericComponent(e.Name())
		if err != nil {
			return 0, fmt.Errorf("db: migration %s: %w", e.Name(), err)
		}
		latest = max(latest, v)
	}
	gm, err := migrations.Go()
	if err != nil {
		return 0, fmt.Errorf("db: migrations: %w", err)
	}
	for _, m := range gm {
		latest = max(latest, m.Version)
	}
	if latest == 0 {
		return 0, errors.New("db: no migrations embedded")
	}
	return latest, nil
}

// recordSchemaVersion writes the applied version to pc.schema_info, which
// the server role reads instead of goose's own table (G0 M13 D19). Only
// `migrate up` calls it, as the migrator.
func recordSchemaVersion(ctx context.Context, sqlDB *sql.DB, version int64) error {
	_, err := sqlDB.ExecContext(ctx, `
		INSERT INTO pc.schema_info (id, version, applied_at) VALUES (1, $1, now())
		ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version, applied_at = EXCLUDED.applied_at
		WHERE pc.schema_info.version IS DISTINCT FROM EXCLUDED.version`, version)
	if err != nil {
		return fmt.Errorf("db: record schema version: %w", err)
	}
	return nil
}

// SchemaVersion reads the schema version `migrate up` recorded; ok is false
// when none is recorded, also when pc.schema_info does not exist yet (a
// database migrated by a binary before 00169, G0 M13 D24).
func (p *Pool) SchemaVersion(ctx context.Context) (v int64, ok bool, err error) {
	err = p.InGlobalTx(ctx, GlobalHealth, func(ctx context.Context, tx GlobalTx) error {
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT to_regclass('pc.schema_info') IS NOT NULL").Scan(&exists); err != nil || !exists {
			return err
		}
		err := tx.QueryRow(ctx, "SELECT version FROM pc.schema_info WHERE id = 1").Scan(&v)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		ok = err == nil
		return err
	}, ReadOnly())
	return v, ok, err
}

// SchemaStatus compares the database's schema with the binary's.
type SchemaStatus int

// Schema states (HR-370).
const (
	SchemaCurrent SchemaStatus = iota
	// SchemaPending: migrations of this binary are not applied yet (or no
	// version is recorded).
	SchemaPending
	// SchemaNewer: the database was migrated by a newer binary.
	SchemaNewer
)

// CheckSchema reports how the recorded schema version compares with the
// binary's latest migration.
func (p *Pool) CheckSchema(ctx context.Context) (SchemaStatus, error) {
	latest, err := LatestMigration()
	if err != nil {
		return SchemaPending, err
	}
	v, ok, err := p.SchemaVersion(ctx)
	switch {
	case err != nil:
		return SchemaPending, err
	case !ok || v < latest:
		return SchemaPending, nil
	case v > latest:
		return SchemaNewer, nil
	default:
		return SchemaCurrent, nil
	}
}
