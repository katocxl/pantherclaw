// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package verifier_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"testing"
)

// fakeDB is a database/sql driver holding one table with a unique id, so
// the SQL store is tested without adding a driver dependency.
type fakeDB struct {
	mu   sync.Mutex
	rows map[string]int64
}

var (
	fakeOnce sync.Once
	fakes    sync.Map // DSN → *fakeDB
)

func openFake(t *testing.T) *sql.DB {
	t.Helper()
	fakeOnce.Do(func() { sql.Register("pcfake", fakeDriver{}) })
	db, err := sql.Open("pcfake", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type fakeDriver struct{}

func (fakeDriver) Open(dsn string) (driver.Conn, error) {
	db, _ := fakes.LoadOrStore(dsn, &fakeDB{rows: map[string]int64{}})
	return fakeConn{db.(*fakeDB)}, nil
}

type fakeConn struct{ db *fakeDB }

func (c fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("use the context methods")
}
func (fakeConn) Close() error              { return nil }
func (fakeConn) Begin() (driver.Tx, error) { return nil, errors.New("no transactions") }

func (c fakeConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	switch q {
	case "INSERT INTO pap_action_tokens_seen (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		"INSERT INTO pap_action_tokens_seen (jti, expires_at) VALUES (?, ?) ON CONFLICT DO NOTHING":
		id := args[0].Value.(string)
		if _, dup := c.db.rows[id]; dup {
			return driver.RowsAffected(0), nil
		}
		c.db.rows[id] = args[1].Value.(int64)
		return driver.RowsAffected(1), nil
	case "DELETE FROM pap_action_tokens_seen WHERE expires_at < $1", "DELETE FROM pap_action_tokens_seen WHERE expires_at < ?":
		n := int64(0)
		for id, exp := range c.db.rows {
			if exp < args[0].Value.(int64) {
				delete(c.db.rows, id)
				n++
			}
		}
		return driver.RowsAffected(n), nil
	}
	return nil, errors.New("unexpected statement: " + q)
}
