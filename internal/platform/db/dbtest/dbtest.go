// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package dbtest provides disposable PostgreSQL databases for integration
// tests (build tag `integration`, BUILD_GUIDE §3.5).
//
// It needs a superuser URL for a throwaway cluster in PC_TEST_PG_ADMIN_URL
// (`task up PROFILE=test` starts one on 127.0.0.1:5433; CI uses a service
// container). Roles are bootstrapped once per cluster with passwords derived
// from the admin password, a migrated template database is built once per
// schema fingerprint, and every test gets its own clone. Templates of other
// fingerprints are kept until nobody has used them for templateTTL, because
// worktrees on branches with different migrations share one cluster. Tests
// connect as pc_app, never as a superuser, because superusers bypass RLS.
package dbtest

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Environment variables.
const (
	AdminURLEnv = "PC_TEST_PG_ADMIN_URL"
	// RequireEnv set to "1" turns a missing database into a failure (CI).
	RequireEnv = "PC_TEST_REQUIRE_DB"
)

// templateLockKey serializes template creation across test processes.
const templateLockKey = 0x70635f746d706c // "pc_tmpl"

// templateTTL is how long a template of another schema fingerprint is kept
// after a test process last started with it. Another worktree may still be
// cloning it, and dropping it then fails that worktree's tests with "template
// database does not exist". A test binary clones only while it runs, and
// `go test` stops it after -timeout (10 minutes by default), so a template
// nobody has started with for a day is no longer in use.
const templateTTL = 24 * time.Hour

// lastUsedPrefix starts the database comment that records when a test
// process last started with a template; an RFC 3339 time follows it.
const lastUsedPrefix = "pantherclaw dbtest template, last used "

// DB is one disposable test database.
type DB struct {
	Name     string
	App      db.Config
	Migrator db.Config
	AuditRO  db.Config
	// Retention is pc_retention, the role of the retention job (HR-198).
	Retention db.Config
	admin     *pgx.ConnConfig
}

type cluster struct {
	admin    *pgx.ConnConfig
	pw       db.RolePasswords
	template string
}

var (
	setupOnce sync.Once
	shared    *cluster
	errSetup  error
)

// New returns a fresh migrated database, dropped when the test ends. It skips
// the test when no admin URL is configured (fails when PC_TEST_REQUIRE_DB=1).
func New(t testing.TB) *DB {
	t.Helper()
	url := os.Getenv(AdminURLEnv)
	if url == "" {
		if os.Getenv(RequireEnv) == "1" {
			t.Fatalf("%s is required (%s=1)", AdminURLEnv, RequireEnv)
		}
		t.Skipf("set %s to run database integration tests (task up PROFILE=test)", AdminURLEnv)
	}
	setupOnce.Do(func() { shared, errSetup = setup(url) })
	if errSetup != nil {
		t.Fatalf("dbtest setup: %v", errSetup)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	name := "pc_test_" + randomHex(8)
	admin, err := pgx.ConnectConfig(ctx, shared.admin)
	if err != nil {
		t.Fatalf("dbtest: connect admin: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	if err := execDDL(ctx, admin, "CREATE DATABASE %s TEMPLATE %s", name, shared.template); err != nil {
		t.Fatalf("dbtest: create database: %v", err)
	}
	t.Cleanup(func() { dropDatabase(context.Background(), shared.admin, name) })
	// Database-level ACLs are not copied from the template.
	if err := withDB(ctx, shared.admin, name, func(c *pgx.Conn) error { return db.BootstrapDatabase(ctx, c) }); err != nil {
		t.Fatalf("dbtest: bootstrap database: %v", err)
	}
	return &DB{
		Name:      name,
		App:       roleConfig(shared.admin, name, db.RoleApp, shared.pw.App, true),
		Migrator:  roleConfig(shared.admin, name, db.RoleMigrator, shared.pw.Migrator, false),
		AuditRO:   roleConfig(shared.admin, name, db.RoleAuditRO, shared.pw.AuditRO, true),
		Retention: roleConfig(shared.admin, name, db.RoleRetention, shared.pw.Retention, true),
		admin:     shared.admin,
	}
}

// AppPool opens a pool as pc_app, closed when the test ends.
func (d *DB) AppPool(t testing.TB) *db.Pool { return d.Pool(t, d.App) }

// Pool opens a pool with c, closed when the test ends.
func (d *DB) Pool(t testing.TB, c db.Config) *db.Pool {
	t.Helper()
	p, err := db.Open(context.Background(), c)
	if err != nil {
		t.Fatalf("dbtest: open pool as %s: %v", c.User, err)
	}
	t.Cleanup(p.Close)
	return p
}

// AdminExec runs a statement as the superuser in this database (for test
// setup that the application roles are deliberately not allowed to do).
func (d *DB) AdminExec(t testing.TB, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	if err := withDB(ctx, d.admin, d.Name, func(c *pgx.Conn) error {
		_, err := c.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("dbtest: admin exec: %v", err)
	}
}

// AdminQueryRow runs a single-row query as the superuser in this database.
func (d *DB) AdminQueryRow(t testing.TB, sql string, args []any, dest ...any) {
	t.Helper()
	ctx := context.Background()
	if err := withDB(ctx, d.admin, d.Name, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, sql, args...).Scan(dest...)
	}); err != nil {
		t.Fatalf("dbtest: admin query: %v", err)
	}
}

// AdminConfig returns a superuser pool config for this database. Use it only
// to prove that privileged roles are refused.
func (d *DB) AdminConfig() db.Config {
	return roleConfig(d.admin, d.Name, d.admin.User, pclog.NewSecret([]byte(d.admin.Password)), false)
}

func setup(url string) (*cluster, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", AdminURLEnv, err)
	}
	if admin.Password == "" {
		return nil, fmt.Errorf("%s must include a password", AdminURLEnv)
	}
	c := &cluster{admin: admin, pw: db.RolePasswords{
		Migrator:  derive(admin.Password, db.RoleMigrator),
		App:       derive(admin.Password, db.RoleApp),
		AuditRO:   derive(admin.Password, db.RoleAuditRO),
		Retention: derive(admin.Password, db.RoleRetention),
	}}
	conn, err := pgx.ConnectConfig(ctx, admin)
	if err != nil {
		return nil, fmt.Errorf("connect admin: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if err := db.BootstrapRoles(ctx, conn, c.pw); err != nil {
		return nil, err
	}
	c.template = "pc_tmpl_" + db.SchemaFingerprint()
	if err := prepareTemplate(ctx, conn, c, time.Now()); err != nil {
		return nil, err
	}
	return c, nil
}

// prepareTemplate builds c.template if it is missing, records that it was
// used at now, and drops the templates of other schema fingerprints that
// nobody has used for templateTTL. A cluster-wide advisory lock serializes it
// across test processes.
func prepareTemplate(ctx context.Context, conn *pgx.Conn, c *cluster, now time.Time) error {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(templateLockKey)); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", int64(templateLockKey))
	}()
	exists, err := databaseExists(ctx, conn, c.template)
	if err != nil {
		return err
	}
	if !exists {
		if err := buildTemplate(ctx, conn, c); err != nil {
			dropDatabase(ctx, c.admin, c.template)
			return err
		}
	}
	if err := markUsed(ctx, conn, c.template, now); err != nil {
		return err
	}
	return dropStaleTemplates(ctx, conn, c, now)
}

// dropStaleTemplates drops the templates of other schema fingerprints whose
// last use is more than templateTTL before now. A template without a
// last-used mark (built before marks existed) gets one instead, so it is
// dropped templateTTL later unless a test process uses it. Both steps are
// best effort, like dropDatabase.
func dropStaleTemplates(ctx context.Context, conn *pgx.Conn, c *cluster, now time.Time) error {
	rows, err := conn.Query(ctx, `SELECT datname, coalesce(shobj_description(oid, 'pg_database'), '')
		FROM pg_database WHERE datname LIKE 'pc\_tmpl\_%' AND datname <> $1`, c.template)
	if err != nil {
		return err
	}
	others, err := pgx.CollectRows(rows, pgx.RowToStructByPos[struct{ Name, Comment string }])
	if err != nil {
		return err
	}
	for _, o := range others {
		last, ok := parseLastUsed(o.Comment)
		switch {
		case !ok:
			_ = markUsed(ctx, conn, o.Name, now)
		case now.Sub(last) > templateTTL:
			dropDatabase(ctx, c.admin, o.Name)
		}
	}
	return nil
}

// markUsed records in the comment of database name that a test process
// started with it at t. COMMENT takes no parameters, so PostgreSQL's format()
// quotes the name and the text.
func markUsed(ctx context.Context, conn *pgx.Conn, name string, t time.Time) error {
	var stmt string
	if err := conn.QueryRow(ctx, "SELECT format('COMMENT ON DATABASE %I IS %L', $1::text, $2::text)",
		name, lastUsedComment(t)).Scan(&stmt); err != nil {
		return err
	}
	_, err := conn.Exec(ctx, stmt) // nosemgrep
	return err
}

func lastUsedComment(t time.Time) string {
	return lastUsedPrefix + t.UTC().Format(time.RFC3339)
}

// parseLastUsed returns the time in a comment written by markUsed, and false
// for any other comment.
func parseLastUsed(comment string) (time.Time, bool) {
	s, ok := strings.CutPrefix(comment, lastUsedPrefix)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func databaseExists(ctx context.Context, conn *pgx.Conn, name string) (bool, error) {
	var exists bool
	err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", name).Scan(&exists)
	return exists, err
}

func buildTemplate(ctx context.Context, conn *pgx.Conn, c *cluster) error {
	if err := execDDL(ctx, conn, "CREATE DATABASE %s", c.template); err != nil {
		return fmt.Errorf("create template: %w", err)
	}
	if err := withDB(ctx, c.admin, c.template, func(tc *pgx.Conn) error { return db.BootstrapDatabase(ctx, tc) }); err != nil {
		return err
	}
	if _, err := db.Migrate(ctx, roleConfig(c.admin, c.template, db.RoleMigrator, c.pw.Migrator, false)); err != nil {
		return err
	}
	return execDDL(ctx, conn, "ALTER DATABASE %s WITH IS_TEMPLATE true ALLOW_CONNECTIONS false", c.template)
}

func roleConfig(admin *pgx.ConnConfig, dbName, user string, pw pclog.Secret[[]byte], unprivileged bool) db.Config {
	c := db.Defaults()
	c.Host = admin.Host
	c.Port = int(admin.Port)
	c.Database = dbName
	c.User = user
	c.Password = pw
	c.SSLMode = "disable"
	c.MaxConns = 10
	c.ApplicationName = "pantherclaw-test"
	c.RequireUnprivileged = unprivileged
	return c
}

func withDB(ctx context.Context, admin *pgx.ConnConfig, name string, fn func(*pgx.Conn) error) error {
	cfg := admin.Copy()
	cfg.Database = name
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	return fn(conn)
}

func dropDatabase(parent context.Context, admin *pgx.ConnConfig, name string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 30*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, admin)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if strings.HasPrefix(name, "pc_tmpl_") {
		_ = execDDL(ctx, conn, "ALTER DATABASE %s WITH IS_TEMPLATE false", name)
	}
	_ = execDDL(ctx, conn, "DROP DATABASE IF EXISTS %s WITH (FORCE)", name)
}

// execDDL runs a database-level DDL statement whose only variable parts are
// identifiers. PostgreSQL cannot bind identifiers as parameters, so each one
// is quoted with pgx.Identifier.Sanitize; the names are generated here, never
// taken from input.
func execDDL(ctx context.Context, conn *pgx.Conn, format string, idents ...string) error {
	quoted := make([]any, len(idents))
	for i, id := range idents {
		quoted[i] = pgx.Identifier{id}.Sanitize()
	}
	stmt := fmt.Sprintf(format, quoted...)
	_, err := conn.Exec(ctx, stmt) // nosemgrep
	return err
}

// derive returns a deterministic role password for the throwaway cluster, so
// concurrent test processes agree on it without coordination.
func derive(adminPassword, role string) pclog.Secret[[]byte] {
	m := hmac.New(sha256.New, []byte(adminPassword))
	m.Write([]byte("pc-test-role|" + role))
	return pclog.NewSecret([]byte(base64.RawURLEncoding.EncodeToString(m.Sum(nil))))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
