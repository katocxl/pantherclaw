// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package verifier

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Dialect is the SQL dialect of a SQLStore's database. The zero Dialect
// is none: a store names its dialect.
type Dialect int

// Supported dialects; other databases implement ReplayStore themselves.
const (
	PostgreSQL Dialect = iota + 1
	SQLite
)

// SQLStore is a ReplayStore in a database that every replica shares
// (Shared is true), through database/sql with the caller's driver. It
// records (aud, jti) pairs in pap_action_tokens_seen (see Schema) with ON
// CONFLICT DO NOTHING, so a second insert of a pair is a replay. One
// database can serve several targets.
type SQLStore struct {
	DB      *sql.DB
	Dialect Dialect
}

// NewSQLStore returns a store on db, refusing a nil database or an
// unknown dialect.
func NewSQLStore(db *sql.DB, d Dialect) (*SQLStore, error) {
	s := &SQLStore{DB: db, Dialect: d}
	if _, err := s.statement(insertSQL); err != nil {
		return nil, err
	}
	return s, nil
}

// Schema is the table the store needs, in either dialect: the brief's
// pap_action_tokens_seen, one row per (aud, jti), kept until expires_at
// (Unix seconds).
const Schema = "CREATE TABLE pap_action_tokens_seen (aud VARCHAR(128) NOT NULL, jti VARCHAR(128) NOT NULL, " +
	"expires_at BIGINT NOT NULL, PRIMARY KEY (aud, jti))"

// PurgeGrace is how long past its keeping time Purge leaves a row.
// Replicas' clocks differ: a replica whose clock is behind the purging
// one still accepts a token until its own exp plus the skew, so the row
// must outlive that by more than any clock difference.
const PurgeGrace = MaxLifetime

// The store's statements, by dialect.
var (
	insertSQL = map[Dialect]string{
		PostgreSQL: "INSERT INTO pap_action_tokens_seen (aud, jti, expires_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
		SQLite:     "INSERT INTO pap_action_tokens_seen (aud, jti, expires_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
	}
	purgeSQL = map[Dialect]string{
		PostgreSQL: "DELETE FROM pap_action_tokens_seen WHERE expires_at < $1",
		SQLite:     "DELETE FROM pap_action_tokens_seen WHERE expires_at < ?",
	}
)

// Shared implements ReplayStore.
func (*SQLStore) Shared() bool { return true }

func (s *SQLStore) statement(m map[Dialect]string) (string, error) {
	q, ok := m[s.Dialect]
	switch {
	case s.DB == nil:
		return "", errors.New("verifier: the SQL replay store has no database")
	case !ok:
		return "", errors.New("verifier: the SQL replay store has no known dialect")
	}
	return q, nil
}

// Use implements ReplayStore.
func (s *SQLStore) Use(ctx context.Context, sp Spend) (bool, error) {
	q, err := s.statement(insertSQL)
	if err != nil {
		return false, err
	}
	res, err := s.DB.ExecContext(ctx, q, sp.Audience, sp.ID, sp.Until.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Purge deletes the rows whose keeping time ended more than PurgeGrace
// before now; run it now and then.
func (s *SQLStore) Purge(ctx context.Context, now time.Time) (int64, error) {
	q, err := s.statement(purgeSQL)
	if err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx, q, now.Add(-PurgeGrace).Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
