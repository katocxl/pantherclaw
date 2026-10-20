// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgtarget is the gateway's client for a customer's PostgreSQL
// database reached through a postgres connection (G0 M14 D16, D58): a
// small pool per connection revision, opened only over TLS (HR-330) and
// only through dial-time egress checks, a role check before any query
// (HR-309), and a runner that executes one statement pgdispatch built in a
// read-only transaction that is always rolled back (HR-308).
//
// A customer database is a target, not PantherClaw's own database
// (ADR-0002): this is the one gateway package that may use pgx.
package pgtarget

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// TLS modes (D15, HR-330).
const (
	SSLVerifyFull = "verify-full"
	SSLRequire    = "require"
)

// Pool limits (D16).
const (
	MaxConns       = 4
	ConnectTimeout = 5 * time.Second
	// maxMessage bounds one protocol message, a row included: every value
	// is cut to pgdispatch.MaxValueChars characters in SQL, so a row of
	// the widest manifest table fits well within it.
	maxMessage = 8 << 20
)

// Endpoint is where and how the gateway reaches the database.
type Endpoint struct {
	Host     string
	Port     int
	Database string
	User     string
	SSLMode  string
	// CAPEM pins the server's CA; empty uses the system roots.
	CAPEM string
	// Internal allows a private address (set only with a step-up).
	Internal bool
}

// Config is one connection revision's endpoint, manifest and password.
type Config struct {
	Endpoint Endpoint
	Manifest pgdispatch.Manifest
	// Password is a Go string because pgx keeps it in the pool's connection
	// configuration, to authenticate each new connection: it cannot be
	// cleared, and it lives in gateway memory for the pool's lifetime, never
	// logged (HR-061; D98).
	Password string
	// Allowed are the operator's allowed egress prefixes (HR-077).
	Allowed []netip.Prefix
	// RootCAs overrides the system roots when no CA is pinned (tests).
	RootCAs *x509.CertPool
}

// Errors.
var (
	// ErrEndpoint: the endpoint breaks HR-330 (plain TLS mode, require
	// without internal and a pinned CA, a bad CA).
	ErrEndpoint = errors.New("pgtarget: the endpoint needs verify-full TLS, or require only for an internal database with a pinned CA")
	// ErrRole: the connection's role could write, or the manifest does not
	// match the database (HR-309).
	ErrRole = errors.New("pgtarget: the connection's role is not a read-only role matching the manifest")
)

// tlsConfig is the TLS the endpoint requires: verify-full checks the chain
// and the host name; require (internal with a pinned CA only) checks the
// chain against the pinned CA without the name. No client certificate is
// ever presented (HR-074).
func tlsConfig(ep Endpoint, roots *x509.CertPool) (*tls.Config, error) {
	var pinned *x509.CertPool
	if ep.CAPEM != "" {
		pinned = x509.NewCertPool()
		rest := []byte(ep.CAPEM)
		n := 0
		for {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				break
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if b.Type != "CERTIFICATE" || err != nil {
				return nil, ErrEndpoint
			}
			pinned.AddCert(c)
			n++
		}
		if n == 0 {
			return nil, ErrEndpoint
		}
	}
	conf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil
		},
	}
	switch {
	case ep.SSLMode == SSLVerifyFull:
		conf.ServerName = ep.Host
		conf.RootCAs = roots
		if pinned != nil {
			conf.RootCAs = pinned
		}
	case ep.SSLMode == SSLRequire && ep.Internal && pinned != nil:
		// The chain must lead to the pinned CA; the name is not checked.
		// VerifyConnection runs on resumed sessions too.
		conf.InsecureSkipVerify = true
		conf.VerifyConnection = func(cs tls.ConnectionState) error {
			certs := cs.PeerCertificates
			if len(certs) == 0 {
				return ErrEndpoint
			}
			inter := x509.NewCertPool()
			for _, c := range certs[1:] {
				inter.AddCert(c)
			}
			_, err := certs[0].Verify(x509.VerifyOptions{Roots: pinned, Intermediates: inter})
			return err
		}
	default:
		return nil, ErrEndpoint
	}
	return conf, nil
}

// dialer checks the address actually connected to at dial time, as the
// HTTP egress client does (HR-071, HR-077): a private address only for an
// internal endpoint, a cloud metadata address never.
func dialer(internal bool, allowed []netip.Prefix) *net.Dialer {
	allowed = append([]netip.Prefix(nil), allowed...)
	return &net.Dialer{
		Timeout:   ConnectTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: unparsable address", httpx.ErrDestinationDenied)
			}
			if Denied(ap.Addr(), internal, allowed) {
				return fmt.Errorf("%w: %s", httpx.ErrDestinationDenied, ap.Addr())
			}
			return nil
		},
	}
}

// Denied reports whether a database address is refused (HR-330, HR-077,
// HR-142; G0 M14 D98). A public address is reached as the HTTP egress client
// reaches it. Any other address (private, loopback, link-local, CGNAT, ...)
// only for an internal endpoint and only inside a prefix the gateway's
// operator allowed: loopback and link-local therefore only when the
// operator lists them, and never on a PantherClaw-hosted gateway, whose
// operator lists none. Cloud metadata addresses are refused always.
func Denied(a netip.Addr, internal bool, allowed []netip.Prefix) bool {
	a = a.WithZone("")
	if httpx.MetadataAddr(a) {
		return true
	}
	if !httpx.DeniedAddr(a, nil) {
		return false
	}
	if !internal {
		return true
	}
	for _, p := range allowed {
		if p.Contains(a) {
			return !a.IsValid() || a.IsUnspecified() || a.IsMulticast()
		}
	}
	return true
}

// Pool is one connection revision's open pool.
type Pool struct {
	pool     *pgxpool.Pool
	manifest pgdispatch.Manifest
	settings []string

	mu sync.Mutex
	// partitioned are the manifest tables the last check found partitioned.
	partitioned map[string]bool
}

// Partitioned reports whether the last role check found table (schema.table)
// partitioned: it is then read whole, any other table with ONLY.
func (p *Pool) Partitioned(table string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.partitioned[table]
}

// Open builds the pool. It dials nothing until the first use; Check makes
// the first connection.
func Open(ctx context.Context, c Config) (*Pool, error) {
	ep := c.Endpoint
	if ep.Port == 0 {
		ep.Port = 5432
	}
	if ep.Host == "" || ep.Port < 1 || ep.Port > 65535 || !pgdispatch.ValidIdentifier(ep.Database) || !pgdispatch.ValidIdentifier(ep.User) {
		return nil, ErrEndpoint
	}
	m, err := c.Manifest.Normalized()
	if err != nil {
		return nil, err
	}
	settings, err := pgdispatch.LocalSettings(m)
	if err != nil {
		return nil, err
	}
	tc, err := tlsConfig(ep, c.RootCAs)
	if err != nil {
		return nil, err
	}
	// An empty connection string still reads PG* environment defaults:
	// every field that matters is set below, and no fallback is kept.
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cc := pc.ConnConfig
	cc.Host, cc.Port, cc.Database, cc.User, cc.Password = ep.Host, uint16(ep.Port), ep.Database, ep.User, c.Password
	cc.TLSConfig, cc.Fallbacks, cc.SSLNegotiation = tc, nil, "postgres"
	cc.ConnectTimeout = ConnectTimeout
	cc.DialFunc = dialer(ep.Internal, c.Allowed).DialContext
	cc.LookupFunc = net.DefaultResolver.LookupHost
	cc.MaxProtocolMessageBodyLen = maxMessage
	cc.RuntimeParams = pgdispatch.StartupParams()
	cc.KerberosSrvName, cc.KerberosSpn, cc.OAuthTokenProvider = "", "", nil
	cc.ValidateConnect, cc.AfterConnect, cc.AfterNetConnect = nil, nil, nil
	// Statements are sent once each, unprepared, in the extended protocol
	// with their parameters.
	cc.DefaultQueryExecMode = pgx.QueryExecModeExec
	pc.MaxConns, pc.MinConns = MaxConns, 0
	pc.MaxConnIdleTime, pc.MaxConnLifetime = 5*time.Minute, 30*time.Minute
	pc.HealthCheckPeriod = time.Minute
	pc.BeforeConnect, pc.AfterConnect, pc.PrepareConn, pc.AfterRelease = nil, nil, nil, nil
	p, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, err
	}
	return &Pool{pool: p, manifest: m, settings: settings}, nil
}

// Close closes the pool.
func (p *Pool) Close() { p.pool.Close() }

// Manifest is the pool's normalized manifest.
func (p *Pool) Manifest() pgdispatch.Manifest { return p.manifest }

// Result is a statement's answer and what the receipt counts.
type Result struct {
	Body            []byte
	Rows            int
	Redacted        int
	Truncated       bool
	TruncatedValues bool
}

// ErrTimeout: the statement ran past its timeout or a lock wait.
var ErrTimeout = errors.New("pgtarget: the statement timed out")

// Run executes one statement in a read-only, repeatable-read transaction
// with the manifest's local settings, and always rolls it back (HR-308).
func (p *Pool) Run(ctx context.Context, st *pgdispatch.Statement) (Result, error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, pgdispatch.BeginSQL); err != nil {
		return Result{}, classify(err)
	}
	// Rolled back on every path, the canceled one included; a connection
	// whose rollback fails is not reused.
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(rctx, pgdispatch.RollbackSQL); err != nil {
			_ = conn.Conn().Close(rctx)
		}
	}()
	for _, s := range p.settings {
		if _, err := conn.Exec(ctx, s); err != nil {
			return Result{}, classify(err)
		}
	}
	enc := pgdispatch.NewEncoder(st, p.manifest.MaxResultBytes)
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
	return Result{Body: enc.Bytes(), Rows: enc.Rows(), Redacted: enc.Redactions(), Truncated: enc.Truncated(), TruncatedValues: enc.TruncatedValues()}, nil
}

// classify maps a statement or lock timeout to ErrTimeout.
func classify(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == "57014" || pe.Code == "55P03") {
		return fmt.Errorf("%w: %s", ErrTimeout, pe.Code)
	}
	return err
}

// MinServerVersion is the oldest server the connector reads (D18).
const MinServerVersion = 130000

// roleSQL is the HR-309 check, one row per finding. It runs as the
// connection's own role and reads only the catalogs.
const roleSQL = `SELECT 'server version ' || current_setting('server_version') WHERE current_setting('server_version_num')::int < $1
UNION ALL SELECT 'superuser' FROM pg_catalog.pg_roles WHERE rolname = current_user AND rolsuper
UNION ALL SELECT 'member of pg_write_all_data' WHERE CASE WHEN EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pg_write_all_data')
THEN pg_catalog.pg_has_role(current_user, 'pg_write_all_data', 'MEMBER') ELSE false END`

// tableSQL checks one manifest table: privileges first, then its columns.
const tableSQL = `SELECT 'can ' || p.priv || ' ' || $1 || '.' || $2 FROM unnest(ARRAY['INSERT','UPDATE','DELETE','TRUNCATE']) AS p(priv)
WHERE pg_catalog.has_table_privilege(pg_catalog.quote_ident($1) || '.' || pg_catalog.quote_ident($2), p.priv)
UNION ALL SELECT 'can ' || p.priv || ' a column of ' || $1 || '.' || $2 FROM unnest(ARRAY['INSERT','UPDATE']) AS p(priv)
WHERE pg_catalog.has_any_column_privilege(pg_catalog.quote_ident($1) || '.' || pg_catalog.quote_ident($2), p.priv)`

// partitionSQL finds the partitions of a partitioned table, at any depth,
// that are not tables.
const partitionSQL = `WITH RECURSIVE d(oid) AS (
  SELECT inhrelid FROM pg_catalog.pg_inherits WHERE inhparent = (pg_catalog.quote_ident($1) || '.' || pg_catalog.quote_ident($2))::regclass
  UNION SELECT i.inhrelid FROM pg_catalog.pg_inherits i JOIN d ON i.inhparent = d.oid)
SELECT $1 || '.' || $2 || ' has a partition that is not a table: ' || c.relname || ' (relkind ' || c.relkind::text || ')'
FROM d JOIN pg_catalog.pg_class c ON c.oid = d.oid WHERE c.relkind NOT IN ('r', 'p')`

// columnSQL lists a table's columns and their types as the catalog has
// them.
const columnSQL = `SELECT a.attname, pg_catalog.format_type(a.atttypid, NULL), c.relkind::text FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND a.attnum > 0 AND NOT a.attisdropped`

// catalogType is each manifest type's name in format_type.
var catalogType = map[pgdispatch.ColumnType]string{
	pgdispatch.TypeText: "text", pgdispatch.TypeInt: "integer", pgdispatch.TypeBigint: "bigint", pgdispatch.TypeNumeric: "numeric",
	pgdispatch.TypeBool: "boolean", pgdispatch.TypeDate: "date", pgdispatch.TypeTimestamptz: "timestamp with time zone",
	pgdispatch.TypeUUID: "uuid",
}

// Check is the HR-309 role check: the server is at least version 13; the
// role is no superuser and is not a member of pg_write_all_data; it cannot insert, update, delete or truncate any
// manifest table, nor insert or update any of its columns; and every
// manifest column exists with its declared type. It returns the findings,
// empty when the role passes; an error means the check could not run.
func (p *Pool) Check(ctx context.Context) ([]string, error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	partitioned := map[string]bool{}
	defer func() {
		p.mu.Lock()
		p.partitioned = partitioned
		p.mu.Unlock()
	}()
	var findings []string
	collect := func(sql string, args ...any) error {
		rows, err := conn.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		f, err := pgx.CollectRows(rows, pgx.RowTo[string])
		findings = append(findings, f...)
		return err
	}
	if err := collect(roleSQL, MinServerVersion); err != nil {
		return nil, err
	}
	for _, t := range p.manifest.Tables {
		rows, err := conn.Query(ctx, columnSQL, t.Schema, t.Name)
		if err != nil {
			return nil, err
		}
		type col struct{ Name, Type, Kind string }
		have, err := pgx.CollectRows(rows, pgx.RowToStructByPos[col])
		if err != nil {
			return nil, err
		}
		if len(have) == 0 {
			findings = append(findings, "table "+t.Ref()+" does not exist")
			continue
		}
		// Ordinary and partitioned tables only: a view reads other tables,
		// and a foreign table makes the database dial out (D98).
		if k := have[0].Kind; k != "r" && k != "p" {
			findings = append(findings, t.Ref()+" is not a table (relkind "+k+")")
			continue
		} else if k == "p" {
			partitioned[t.Ref()] = true
			// Every partition, at any depth, is a table too: a foreign
			// partition would make the database dial out (D105).
			if err := collect(partitionSQL, t.Schema, t.Name); err != nil {
				return nil, err
			}
		}
		types := make(map[string]string, len(have))
		for _, c := range have {
			types[c.Name] = c.Type
		}
		for _, c := range t.Columns {
			switch got, ok := types[c.Name]; {
			case !ok:
				findings = append(findings, "column "+t.Ref()+"."+c.Name+" does not exist")
			case got != catalogType[c.Type]:
				findings = append(findings, "column "+t.Ref()+"."+c.Name+" is "+strconv.Quote(got)+", not "+string(c.Type))
			}
		}
		if err := collect(tableSQL, t.Schema, t.Name); err != nil {
			return nil, err
		}
	}
	return findings, nil
}

// Handshake reads a simulated database's handshake (G0 M14 D110): the
// kind and connection pantherclaw_sim.handshake names, in a read-only
// transaction. A database without one answers an error.
func (p *Pool) Handshake(ctx context.Context) (kind, connection string, err error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return "", "", err
	}
	defer conn.Release()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	rows, err := tx.Query(ctx, `SELECT kind, connection FROM pantherclaw_sim.handshake LIMIT 2`)
	if err != nil {
		return "", "", err
	}
	type row struct{ Kind, Connection string }
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
	if err != nil {
		return "", "", err
	}
	if len(got) != 1 {
		return "", "", fmt.Errorf("pgtarget: %d handshake rows, want exactly one", len(got))
	}
	return got[0].Kind, got[0].Connection, nil
}
