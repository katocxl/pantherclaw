// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package db is PantherClaw's PostgreSQL access layer (ADR-0003).
//
// Tenant isolation is enforced twice: every repository method takes a typed
// OrgID and runs inside InTenantTx, which sets app.org_id with set_config at
// transaction start (HR-051); and every tenant table has RLS ENABLEd and
// FORCEd with a policy that matches nothing when the setting is missing
// (HR-052, HR-053). Connections carry statement, lock and idle-in-transaction
// timeouts as startup parameters, so `RESET ALL` on release (HR-052) restores
// them instead of clearing them (HR-057).
package db

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Schema is the single schema that holds PantherClaw's objects.
const Schema = "pc"

// Config describes one connection pool. Passwords come from secret files.
type Config struct {
	// Host is one host, or a comma-separated list of hosts for a primary
	// and its standbys, each optionally with its own ":port" (G0 M19 D202).
	// Every connection targets the read-write primary
	// (target_session_attrs=read-write) and verifies TLS against the host
	// it reaches (HR-497). A stable endpoint (a managed service or a proxy)
	// is the alternative: one host that always names the primary.
	Host string
	Port int
	// Hosts, when set, replaces Host and Port.
	Hosts    []Endpoint
	Database string
	User     string
	Password pclog.Secret[[]byte]
	// SSLMode is a libpq sslmode. "disable" is accepted only for loopback
	// hosts; anything else requires "verify-full" (or "verify-ca").
	SSLMode     string
	SSLRootCert string

	MaxConns         int32
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleInTxTimeout  time.Duration
	ApplicationName  string

	// RequireUnprivileged makes every new connection verify that its role is
	// neither superuser nor BYPASSRLS. Set it for the application pool so a
	// misconfigured DSN fails closed instead of silently bypassing RLS.
	RequireUnprivileged bool

	// Tracer, when set, traces every query (telemetry.QueryTracer: spans
	// named by the sqlc query name only, G0 M13 D30).
	Tracer pgx.QueryTracer
}

// Endpoint is one database host and port.
type Endpoint struct {
	Host string
	Port int
}

// endpoints lists the hosts to try, in order: Hosts, or else Host split at
// commas, each with Port unless it names its own.
func (c Config) endpoints() ([]Endpoint, error) {
	if len(c.Hosts) > 0 {
		return c.Hosts, nil
	}
	var out []Endpoint
	for _, h := range strings.Split(c.Host, ",") {
		h = strings.TrimSpace(h)
		e := Endpoint{Host: h, Port: c.Port}
		if host, port, err := net.SplitHostPort(h); err == nil {
			p, err := strconv.Atoi(port)
			if err != nil {
				return nil, fmt.Errorf("db: host %q has a bad port", h)
			}
			e = Endpoint{Host: host, Port: p}
		}
		out = append(out, e)
	}
	return out, nil
}

// Defaults returns a Config with PantherClaw's default limits.
func Defaults() Config {
	return Config{
		Host: "127.0.0.1", Port: 5432, Database: "pantherclaw", SSLMode: "verify-full",
		MaxConns: 20, StatementTimeout: 5 * time.Second, LockTimeout: 2 * time.Second,
		IdleInTxTimeout: 10 * time.Second, ApplicationName: "pantherclaw",
	}
}

// Validate checks the configuration.
func (c Config) Validate() error {
	var errs []error
	if (c.Host == "" && len(c.Hosts) == 0) || c.Database == "" || c.User == "" {
		errs = append(errs, errors.New("db: host, database and user are required"))
	}
	eps, err := c.endpoints()
	if err != nil {
		errs = append(errs, err)
	}
	loopback := true
	for _, e := range eps {
		if e.Host == "" || strings.ContainsAny(e.Host, ", '\\") {
			errs = append(errs, fmt.Errorf("db: host %q not allowed", e.Host))
		}
		if e.Port < 1 || e.Port > 65535 {
			errs = append(errs, errors.New("db: port out of range"))
		}
		loopback = loopback && isLoopback(e.Host)
	}
	if !c.Password.IsSet() {
		errs = append(errs, errors.New("db: password file is required"))
	}
	switch c.SSLMode {
	case "verify-full":
	case "verify-ca":
		// verify-ca does not check the host name, so with several hosts
		// any one's certificate would pass for another's (HR-497).
		if len(eps) > 1 {
			errs = append(errs, errors.New("db: several hosts need sslmode=verify-full (HR-497)"))
		}
	case "disable":
		if !loopback {
			errs = append(errs, errors.New("db: sslmode=disable is only allowed for loopback hosts"))
		}
	default:
		errs = append(errs, fmt.Errorf("db: sslmode %q not allowed (use verify-full)", c.SSLMode))
	}
	if c.MaxConns < 1 || c.MaxConns > 1000 {
		errs = append(errs, errors.New("db: max conns must be 1..1000"))
	}
	for name, d := range map[string]time.Duration{
		"statement timeout": c.StatementTimeout, "lock timeout": c.LockTimeout,
		"idle-in-transaction timeout": c.IdleInTxTimeout,
	} {
		if d < 10*time.Millisecond || d > 10*time.Minute {
			errs = append(errs, fmt.Errorf("db: %s must be between 10ms and 10m", name))
		}
	}
	return errors.Join(errs...)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Pool is a pgx connection pool configured for PantherClaw.
type Pool struct {
	pool *pgxpool.Pool
	// timeline watches for a promotion while the pool runs (D213).
	timeline *timelineWatch
}

// Open creates a pool and checks connectivity.
func Open(ctx context.Context, c Config) (*Pool, error) {
	pc, err := c.poolConfig()
	if err != nil {
		return nil, err
	}
	w := &timelineWatch{}
	verify := pc.AfterConnect
	pc.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if err := verify(ctx, conn); err != nil {
			return err
		}
		return w.check(ctx, conn)
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("db: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &Pool{pool: pool, timeline: w}, nil
}

func (c Config) poolConfig() (*pgxpool.Config, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	eps, err := c.endpoints()
	if err != nil {
		return nil, err
	}
	hosts, ports := make([]string, len(eps)), make([]string, len(eps))
	for i, e := range eps {
		hosts[i], ports[i] = e.Host, strconv.Itoa(e.Port)
	}
	// Keyword/value form without the password; the password is set on the
	// parsed config so it never appears in a connection string. Each host
	// gets its own TLS configuration naming that host (verify-full,
	// HR-497), and only a read-write primary is accepted (HR-495).
	kv := []string{
		"host=" + quoteKV(strings.Join(hosts, ",")), "port=" + quoteKV(strings.Join(ports, ",")),
		"dbname=" + quoteKV(c.Database), "user=" + quoteKV(c.User), "sslmode=" + c.SSLMode,
		"connect_timeout=5", "target_session_attrs=read-write",
	}
	if c.SSLRootCert != "" {
		kv = append(kv, "sslrootcert="+quoteKV(c.SSLRootCert))
	}
	pc, err := pgxpool.ParseConfig(strings.Join(kv, " "))
	if err != nil {
		return nil, fmt.Errorf("db: parse config: %w", err)
	}
	pc.ConnConfig.Password = string(c.Password.Reveal())
	// A primary that vanishes without closing its connections (a host or
	// network failure) is noticed within about 11 s, so pooled
	// and LISTEN connections fail and reconnect to the promoted primary
	// instead of waiting on a dead socket (G0 M19 D202).
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAliveConfig: net.KeepAliveConfig{
		Enable: true, Idle: 5 * time.Second, Interval: 2 * time.Second, Count: 3,
	}}
	pc.ConnConfig.DialFunc = dialer.DialContext
	pc.MaxConns = c.MaxConns
	pc.MaxConnLifetime = 30 * time.Minute
	pc.MaxConnIdleTime = 5 * time.Minute
	// Startup parameters become the session defaults that RESET ALL restores.
	pc.ConnConfig.RuntimeParams = map[string]string{
		"search_path":                         Schema,
		"statement_timeout":                   ms(c.StatementTimeout),
		"lock_timeout":                        ms(c.LockTimeout),
		"idle_in_transaction_session_timeout": ms(c.IdleInTxTimeout),
		"application_name":                    c.ApplicationName,
		"row_security":                        "on",
	}
	pc.ConnConfig.Tracer = c.Tracer
	want := c
	pc.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error { return verifySession(ctx, conn, want) }
	pc.AfterRelease = func(conn *pgx.Conn) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := conn.Exec(ctx, "RESET ALL")
		return err == nil
	}
	return pc, nil
}

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }

func quoteKV(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`) + "'"
}

// ErrSessionMisconfigured reports a connection that does not meet HR-055/057.
var ErrSessionMisconfigured = errors.New("db: session misconfigured")

// ErrNotPrimary reports a connection that reached a standby. No pool ever
// uses one, not even for reads: while no read-write primary answers, every
// transaction fails and nothing is decided (G0 M19 D202, G11, HR-495).
var ErrNotPrimary = errors.New("db: host is a standby, not the read-write primary")

// verifySession runs on every new connection (HR-057, HR-055, HR-495).
func verifySession(ctx context.Context, conn *pgx.Conn, c Config) error {
	var recovery, timeoutsOK, pathOK, super, bypass bool
	err := conn.QueryRow(ctx, `
		SELECT pg_is_in_recovery(),
		       current_setting('statement_timeout')::interval = make_interval(secs => $1::float8 / 1000)
		   AND current_setting('lock_timeout')::interval = make_interval(secs => $2::float8 / 1000)
		   AND current_setting('idle_in_transaction_session_timeout')::interval = make_interval(secs => $3::float8 / 1000),
		       current_setting('search_path') = $4,
		       r.rolsuper, r.rolbypassrls
		FROM pg_roles r WHERE r.rolname = current_user`,
		c.StatementTimeout.Milliseconds(), c.LockTimeout.Milliseconds(), c.IdleInTxTimeout.Milliseconds(), Schema,
	).Scan(&recovery, &timeoutsOK, &pathOK, &super, &bypass)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSessionMisconfigured, err)
	}
	if recovery {
		return ErrNotPrimary
	}
	if !timeoutsOK || !pathOK {
		return fmt.Errorf("%w: timeouts or search_path not applied (HR-057)", ErrSessionMisconfigured)
	}
	if c.RequireUnprivileged && (super || bypass) {
		return fmt.Errorf("%w: role %q is superuser or BYPASSRLS; refusing to use it for the application (HR-055)",
			ErrSessionMisconfigured, c.User)
	}
	return nil
}

// Close closes the pool.
func (p *Pool) Close() { p.pool.Close() }

// Ping checks connectivity.
func (p *Pool) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// Pgx returns the underlying pool for infrastructure that needs it (River).
// Application code uses InTenantTx / InGlobalTx.
func (p *Pool) Pgx() *pgxpool.Pool { return p.pool }
