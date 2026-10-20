// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgtargettest gives tests a target database for the postgres
// connector (G0 M14 D19): a fresh database on the test cluster with the
// fixture schema, a read-only role and a write-capable role, reached
// through a TLS-terminating proxy with its own CA, so the connector is
// tested exactly as it runs (verify-full, HR-330) although the test
// cluster itself speaks no TLS.
package pgtargettest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget"
)

// Environment, as internal/platform/db/dbtest reads it.
const (
	adminURLEnv = "PC_TEST_PG_ADMIN_URL"
	requireEnv  = "PC_TEST_REQUIRE_DB"
)

// Host is the name the proxy's certificate is issued for.
const Host = "localhost"

// Target is one fixture database.
type Target struct {
	// Database is the fixture database's name.
	Database string
	// ReadOnly and Writer are its two roles and their passwords.
	ReadOnly, Writer         string
	ReadOnlyPass, WriterPass string
	// Port is the TLS proxy's port on 127.0.0.1; CAPEM its CA.
	Port  int
	CAPEM string
	admin *pgx.ConnConfig
}

// Customers are the fixture customer ids: 1 and 2 have orders and
// tickets, 3 has none.
var Customers = []int64{1, 2, 3}

// Manifest is the D19 fixture manifest.
func Manifest() pgdispatch.Manifest {
	return pgdispatch.Manifest{Tables: []pgdispatch.Table{
		{Schema: "shop", Name: "customers", ScopeKey: "customer", ScopeColumn: "id", Columns: []pgdispatch.Column{
			{Name: "id", Type: pgdispatch.TypeBigint, Class: pgdispatch.ClassPublic},
			{Name: "name", Type: pgdispatch.TypeText, Class: pgdispatch.ClassPII},
			{Name: "email", Type: pgdispatch.TypeText, Class: pgdispatch.ClassPII},
			{Name: "tier", Type: pgdispatch.TypeText, Class: pgdispatch.ClassPublic},
			{Name: "ssn", Type: pgdispatch.TypeText, Class: pgdispatch.ClassSecret},
		}},
		{Schema: "shop", Name: "orders", ScopeKey: "customer", ScopeColumn: "customer_id", Columns: []pgdispatch.Column{
			{Name: "id", Type: pgdispatch.TypeBigint, Class: pgdispatch.ClassPublic},
			{Name: "customer_id", Type: pgdispatch.TypeBigint, Class: pgdispatch.ClassPublic},
			{Name: "amount", Type: pgdispatch.TypeNumeric, Class: pgdispatch.ClassInternal},
			{Name: "status", Type: pgdispatch.TypeText, Class: pgdispatch.ClassPublic},
		}},
		{Schema: "support", Name: "tickets", ScopeKey: "customer", ScopeColumn: "customer_id", Columns: []pgdispatch.Column{
			{Name: "id", Type: pgdispatch.TypeBigint, Class: pgdispatch.ClassPublic},
			{Name: "customer_id", Type: pgdispatch.TypeBigint, Class: pgdispatch.ClassPublic},
			{Name: "subject", Type: pgdispatch.TypeText, Class: pgdispatch.ClassInternal},
		}},
	}}
}

// fixture is the schema and data (D19). Customer 1 has 6 paid orders and
// 2 refunded ones; customer 2 has 3 paid orders (a group below the
// default minimum of 5).
const fixture = `
CREATE SCHEMA shop;
CREATE SCHEMA support;
CREATE TABLE shop.customers (id bigint PRIMARY KEY, name text, email text, tier text, ssn text);
CREATE TABLE shop.orders (id bigint PRIMARY KEY, customer_id bigint REFERENCES shop.customers, amount numeric, status text);
CREATE TABLE support.tickets (id bigint PRIMARY KEY, customer_id bigint REFERENCES shop.customers, subject text);
INSERT INTO shop.customers VALUES
  (1, 'Ada Lovelace', 'ada@example.com', 'gold', '111-11-1111'),
  (2, 'Alan Turing', 'alan@example.com', 'silver', '222-22-2222'),
  (3, 'Grace Hopper', 'grace@example.com', 'gold', '333-33-3333');
INSERT INTO shop.orders VALUES
  (10, 1, 10.00, 'paid'), (11, 1, 20.00, 'paid'), (12, 1, 30.00, 'paid'), (13, 1, 40.00, 'paid'),
  (14, 1, 50.00, 'paid'), (15, 1, 60.00, 'paid'), (16, 1, 5.00, 'refunded'), (17, 1, 6.00, 'refunded'),
  (20, 2, 7.00, 'paid'), (21, 2, 8.00, 'paid'), (22, 2, 9.00, 'paid');
INSERT INTO support.tickets VALUES (100, 1, 'Refund please'), (101, 2, 'Where is my order');
`

// Option changes a fixture.
type Option func(*options)

type options struct{ nameOnly bool }

// NameOnly issues the proxy's certificate for Host alone, without the
// loopback address, so that dialing 127.0.0.1 fails verify-full.
func NameOnly() Option { return func(o *options) { o.nameOnly = true } }

// New creates a fixture database, its roles and a TLS proxy to it, removed
// when the test ends. It skips the test when no admin URL is configured
// (fails when PC_TEST_REQUIRE_DB=1).
func New(t testing.TB, opts ...Option) *Target {
	t.Helper()
	var o options
	for _, f := range opts {
		f(&o)
	}
	url := os.Getenv(adminURLEnv)
	if url == "" {
		if os.Getenv(requireEnv) == "1" {
			t.Fatalf("%s is required (%s=1)", adminURLEnv, requireEnv)
		}
		t.Skipf("set %s to run the postgres connector tests (task up PROFILE=test)", adminURLEnv)
	}
	admin, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatalf("pgtargettest: admin URL: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	suffix := random(6)
	tg := &Target{
		Database: "pc_pgt_" + suffix, ReadOnly: "pc_pgt_ro_" + suffix, Writer: "pc_pgt_rw_" + suffix,
		ReadOnlyPass: random(16), WriterPass: random(16), admin: admin,
	}
	exec := func(cfg *pgx.ConnConfig, sqls ...string) {
		t.Helper()
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("pgtargettest: connect: %v", err)
		}
		defer func() { _ = c.Close(ctx) }()
		for _, s := range sqls {
			if _, err := c.Exec(ctx, s); err != nil {
				t.Fatalf("pgtargettest: %s: %v", s, err)
			}
		}
	}
	quote := func(s string) string { return pgx.Identifier{s}.Sanitize() }
	exec(admin,
		"CREATE DATABASE "+quote(tg.Database),
		"CREATE ROLE "+quote(tg.ReadOnly)+" LOGIN PASSWORD '"+tg.ReadOnlyPass+"'",
		"CREATE ROLE "+quote(tg.Writer)+" LOGIN PASSWORD '"+tg.WriterPass+"'",
	)
	t.Cleanup(func() {
		c, err := pgx.ConnectConfig(context.Background(), admin)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+quote(tg.Database)+" WITH (FORCE)")
		_, _ = c.Exec(context.Background(), "DROP ROLE IF EXISTS "+quote(tg.ReadOnly))
		_, _ = c.Exec(context.Background(), "DROP ROLE IF EXISTS "+quote(tg.Writer))
	})
	inDB := admin.Copy()
	inDB.Database = tg.Database
	exec(inDB, fixture,
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
		"GRANT USAGE ON SCHEMA shop, support TO "+quote(tg.ReadOnly)+", "+quote(tg.Writer),
		"GRANT SELECT ON ALL TABLES IN SCHEMA shop, support TO "+quote(tg.ReadOnly),
		"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA shop, support TO "+quote(tg.Writer),
	)
	tg.Port, tg.CAPEM = proxy(t, net.JoinHostPort(admin.Host, strconv.Itoa(int(admin.Port))), o.nameOnly)
	return tg
}

// AdminExec runs statements as the cluster's superuser in the fixture
// database.
func (tg *Target) AdminExec(t testing.TB, sqls ...string) {
	t.Helper()
	cfg := tg.admin.Copy()
	cfg.Database = tg.Database
	c, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgtargettest: connect: %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	for _, s := range sqls {
		if _, err := c.Exec(context.Background(), s); err != nil {
			t.Fatalf("pgtargettest: %s: %v", s, err)
		}
	}
}

// Config is a pgtarget configuration for the role (the read-only role
// unless writer), verify-full against the proxy's CA. The proxy listens
// on loopback, so the endpoint is internal.
func (tg *Target) Config(writer bool) pgtarget.Config {
	user, pass := tg.ReadOnly, tg.ReadOnlyPass
	if writer {
		user, pass = tg.Writer, tg.WriterPass
	}
	return pgtarget.Config{
		Endpoint: pgtarget.Endpoint{
			Host: Host, Port: tg.Port, Database: tg.Database, User: user, SSLMode: pgtarget.SSLVerifyFull, CAPEM: tg.CAPEM, Internal: true,
		},
		Manifest: Manifest(),
		Password: pass,
		// The proxy is on loopback: the operator of a customer-hosted gateway
		// allows it explicitly (D98).
		Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}
}

// proxy listens on 127.0.0.1 and terminates TLS for the backend: it answers
// a client's SSLRequest with 'S', completes TLS with a certificate for Host
// from a fresh CA, and relays the plaintext to the backend.
func proxy(t testing.TB, backend string, nameOnly bool) (int, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pgtargettest CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: Host}, DNSNames: []string{Host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if !nameOnly {
		leaf.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup closes the client connections still open (a pool the test
	// did not close), so no relay outlives the test.
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		open   []net.Conn
		closed bool
	)
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		closed = true
		for _, c := range open {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = c.Close()
				return
			}
			open = append(open, c)
			mu.Unlock()
			wg.Go(func() { relay(context.Background(), c, conf, backend) })
		}
	})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return l.Addr().(*net.TCPAddr).Port, string(caPEM)
}

// sslRequest is the SSLRequest code.
const sslRequest = 80877103

func relay(ctx context.Context, c net.Conn, conf *tls.Config, backend string) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var hdr [8]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || binary.BigEndian.Uint32(hdr[:4]) != 8 || binary.BigEndian.Uint32(hdr[4:]) != sslRequest {
		return // only TLS is served
	}
	if _, err := c.Write([]byte{'S'}); err != nil {
		return
	}
	tc := tls.Server(c, conf)
	if err := tc.HandshakeContext(ctx); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	b, err := (&net.Dialer{}).DialContext(ctx, "tcp", backend)
	if err != nil {
		return
	}
	defer func() { _ = b.Close() }()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, tc); done <- struct{}{} }()
	go func() { _, _ = io.Copy(tc, b); done <- struct{}{} }()
	<-done
}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Lock holds an ACCESS EXCLUSIVE lock on a fixture table, as a migration
// would, until release: a read of it waits for its lock timeout.
func (tg *Target) Lock(t testing.TB, table string) (release func()) {
	t.Helper()
	cfg := tg.admin.Copy()
	cfg.Database = tg.Database
	c, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgtargettest: connect: %v", err)
	}
	ctx := context.Background()
	if _, err := c.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, "LOCK TABLE "+table+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	return func() {
		_, _ = c.Exec(ctx, "ROLLBACK")
		_ = c.Close(ctx)
	}
}

// URL is the dev seed --postgres URL of the read-only role (D21): no
// password, the loopback literal (a simulated connection needs one, D110),
// verify-full against the CA written to caFile, internal.
func (tg *Target) URL(caFile string) string {
	return "postgres://" + tg.ReadOnly + "@127.0.0.1:" + strconv.Itoa(tg.Port) + "/" + tg.Database +
		"?sslmode=verify-full&internal=true&sslrootcert=" + caFile
}

// SimHandshake makes the fixture database answer the simulated-connection
// handshake for connection (D110): the table pantherclaw_sim.handshake,
// readable by the read-only role, holds ('postgres', connection).
func (tg *Target) SimHandshake(t testing.TB, connection string) {
	t.Helper()
	q := pgx.Identifier{tg.ReadOnly}.Sanitize()
	tg.AdminExec(t,
		"CREATE SCHEMA IF NOT EXISTS pantherclaw_sim",
		"CREATE TABLE IF NOT EXISTS pantherclaw_sim.handshake (kind text NOT NULL, connection text NOT NULL)",
		"DELETE FROM pantherclaw_sim.handshake",
		"INSERT INTO pantherclaw_sim.handshake VALUES ('postgres', '"+strings.ReplaceAll(connection, "'", "")+"')",
		"GRANT USAGE ON SCHEMA pantherclaw_sim TO "+q,
		"GRANT SELECT ON pantherclaw_sim.handshake TO "+q,
	)
}
