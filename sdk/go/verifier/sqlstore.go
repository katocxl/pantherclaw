// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package verifier

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Dialect is the SQL dialect of a SQLStore's database.
type Dialect int

// Supported dialects; other databases implement ReplayStore themselves.
const (
	PostgreSQL Dialect = iota
	SQLite
)

// SQLStore is a ReplayStore in a database that every replica shares
// (Shared is true), through database/sql with the caller's driver. It
// records ids in pap_action_tokens_seen (see Schema) with ON CONFLICT DO
// NOTHING, so a second insert of an id is a replay.
type SQLStore struct {
	DB      *sql.DB
	Dialect Dialect
}

// Schema is the table the store needs.
const Schema = "CREATE TABLE pap_action_tokens_seen (jti VARCHAR(128) PRIMARY KEY, expires_at BIGINT NOT NULL)"

// The store's statements, by dialect.
var (
	insertSQL = map[Dialect]string{
		PostgreSQL: "INSERT INTO pap_action_tokens_seen (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		SQLite:     "INSERT INTO pap_action_tokens_seen (jti, expires_at) VALUES (?, ?) ON CONFLICT DO NOTHING",
	}
	purgeSQL = map[Dialect]string{
		PostgreSQL: "DELETE FROM pap_action_tokens_seen WHERE expires_at < $1",
		SQLite:     "DELETE FROM pap_action_tokens_seen WHERE expires_at < ?",
	}
)

// Shared implements ReplayStore.
func (*SQLStore) Shared() bool { return true }

func statement(m map[Dialect]string, d Dialect) (string, error) {
	q, ok := m[d]
	if !ok {
		return "", errors.New("verifier: unknown SQL dialect")
	}
	return q, nil
}

// Use implements ReplayStore.
func (s *SQLStore) Use(ctx context.Context, sp Spend) (bool, error) {
	q, err := statement(insertSQL, s.Dialect)
	if err != nil {
		return false, err
	}
	res, err := s.DB.ExecContext(ctx, q, sp.ID, sp.Until.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Purge deletes ids whose keeping time ended before now; run it now and
// then.
func (s *SQLStore) Purge(ctx context.Context, now time.Time) (int64, error) {
	q, err := statement(purgeSQL, s.Dialect)
	if err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx, q, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
