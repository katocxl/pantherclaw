// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtarget

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
)

// The pool of a vectorstore connection (G0 M30 D922-D924): the same TLS,
// egress and pool settings as a postgres connection's, a role check that
// refuses a superuser (the read-only check does not apply: the role
// writes the one table), queries in a read-only transaction that is always
// rolled back, and writes that commit.

// VectorConfig is one vectorstore connection revision's endpoint and
// password.
type VectorConfig struct {
	Endpoint Endpoint
	// Password lives in gateway memory for the pool's lifetime, never
	// logged, as Config.Password (HR-061).
	Password string
	Allowed  []netip.Prefix
	RootCAs  *x509.CertPool
}

// ErrCommitUnknown: a write's COMMIT did not answer, so whether it took
// effect is not known.
var ErrCommitUnknown = errors.New("pgtarget: the commit did not answer; the write's outcome is unknown")

// vectorRoleSQL is the vectorstore role check (D924), one row per finding.
const vectorRoleSQL = `SELECT 'superuser' FROM pg_catalog.pg_roles WHERE rolname = current_user AND rolsuper`

// VectorPool is one vectorstore connection revision's open pool.
type VectorPool struct {
	pool *pgxpool.Pool

	mu sync.Mutex
	// settings are the last passed check's SET LOCAL statements, with the
	// vector extension's schema; nil until a check passes.
	settings []string
}

// OpenVector builds the pool. It dials nothing until the first use.
func OpenVector(ctx context.Context, c VectorConfig) (*VectorPool, error) {
	ep := c.Endpoint
	if ep.Port == 0 {
		ep.Port = 5432
	}
	if ep.Host == "" || ep.Port < 1 || ep.Port > 65535 || !pgdispatch.ValidIdentifier(ep.Database) || !pgdispatch.ValidIdentifier(ep.User) {
		return nil, ErrEndpoint
	}
	p, err := newPool(ctx, ep, c.Password, c.Allowed, c.RootCAs)
	if err != nil {
		return nil, err
	}
	return &VectorPool{pool: p}, nil
}

// Close closes the pool.
func (p *VectorPool) Close() { p.pool.Close() }

// Check refuses a superuser role and finds the vector extension (D924). It
// returns the findings, empty when the role passes; an error means the
// check could not run.
func (p *VectorPool) Check(ctx context.Context) ([]string, error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	rows, err := conn.Query(ctx, vectorRoleSQL)
	if err != nil {
		return nil, err
	}
	findings, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	rows, err = conn.Query(ctx, pgdispatch.VectorExtensionSQL)
	if err != nil {
		return nil, err
	}
	schemas, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	var settings []string
	if len(schemas) != 1 {
		findings = append(findings, "the vector extension is not installed")
	} else if settings, err = pgdispatch.VectorSettings(schemas[0]); err != nil {
		findings = append(findings, "the vector extension's schema is not a plain identifier")
	}
	p.mu.Lock()
	p.settings = nil
	if len(findings) == 0 {
		p.settings = settings
	}
	p.mu.Unlock()
	return findings, nil
}

func (p *VectorPool) current() ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.settings == nil {
		return nil, ErrRole
	}
	return p.settings, nil
}

// Query runs a vector_query in a read-only transaction that is always
// rolled back, encoding at most maxBytes of answer.
func (p *VectorPool) Query(ctx context.Context, st *pgdispatch.Statement, maxBytes int) (Result, error) {
	settings, err := p.current()
	if err != nil {
		return Result{}, err
	}
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, pgdispatch.BeginSQL); err != nil {
		return Result{}, classify(err)
	}
	defer rollback(ctx, conn)
	for _, s := range settings {
		if _, err := conn.Exec(ctx, s); err != nil {
			return Result{}, classify(err)
		}
	}
	enc := pgdispatch.NewEncoder(st, maxBytes)
	rows, err := conn.Query(ctx, st.SQL, st.Args...)
	if err != nil {
		return Result{}, classify(err)
	}
	defer rows.Close()
	row := make([]*string, st.Selected())
	dest := make([]any, len(row))
	for i := range row {
		dest[i] = &row[i]
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return Result{}, err
		}
		more, err := enc.Add(row)
		if err != nil {
			return Result{}, err
		}
		if !more {
			break
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Result{}, classify(err)
	}
	return Result{Body: enc.Bytes(), Rows: enc.Rows(), Truncated: enc.Truncated(), TruncatedValues: enc.TruncatedValues()}, nil
}

// Exec runs a vector_upsert or vector_delete and commits it, returning the
// rows it touched. An error before COMMIT is sent changed nothing; a COMMIT
// that does not answer is ErrCommitUnknown.
func (p *VectorPool) Exec(ctx context.Context, st *pgdispatch.Statement) (int64, error) {
	settings, err := p.current()
	if err != nil {
		return 0, err
	}
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, pgdispatch.VectorWriteBeginSQL); err != nil {
		return 0, classify(err)
	}
	committing := false
	defer func() {
		if !committing {
			rollback(ctx, conn)
		}
	}()
	for _, s := range settings {
		if _, err := conn.Exec(ctx, s); err != nil {
			return 0, classify(err)
		}
	}
	tag, err := conn.Exec(ctx, st.SQL, st.Args...)
	if err != nil {
		return 0, classify(err)
	}
	committing = true
	if _, err := conn.Exec(ctx, pgdispatch.CommitSQL); err != nil {
		_ = conn.Conn().Close(context.WithoutCancel(ctx))
		return 0, errors.Join(ErrCommitUnknown, err)
	}
	return tag.RowsAffected(), nil
}

// rollback ends a transaction; a connection whose rollback fails is not
// reused.
func rollback(ctx context.Context, conn *pgxpool.Conn) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(rctx, pgdispatch.RollbackSQL); err != nil {
		_ = conn.Conn().Close(rctx)
	}
}
