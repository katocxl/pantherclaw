// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcpostgres "github.com/katocxl/pantherclaw/packages/pc-postgres"
)

// The development postgres connection (G0 M14 D21): pc.postgres over the
// D19 fixture manifest.
const devPostgresConnectionName = "warehouse"

// postgresOperations are what the dev grant allows with --postgres.
var postgresOperations = []string{"postgres.rows.read", "postgres.rows.aggregate", "postgres.tables.read"}

// errPostgresDSN: the --postgres file is not one postgres URL.
var errPostgresDSN = errors.New("dev seed: --postgres names a file holding one URL " +
	"postgres://USER@HOST[:PORT]/DATABASE?sslmode=verify-full|require[&sslrootcert=CA.pem][&internal=true]; " +
	"the password is sealed separately")

// devPostgresConfig reads the --postgres file: where the gateway reaches
// the database, without the password, which pclaw seal adds as the
// connection's credential. The manifest is the D19 fixture's.
func devPostgresConfig(path string) (capp.PostgresConfig, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: an operator's file, development only
	if err != nil {
		return capp.PostgresConfig{}, fmt.Errorf("dev seed: --postgres: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User == nil || u.Hostname() == "" || u.Fragment != "" {
		return capp.PostgresConfig{}, errPostgresDSN
	}
	if _, has := u.User.Password(); has {
		return capp.PostgresConfig{}, fmt.Errorf("%w (the URL holds a password)", errPostgresDSN)
	}
	q := u.Query()
	c := capp.PostgresConfig{
		Host: u.Hostname(), Database: strings.TrimPrefix(u.Path, "/"), User: u.User.Username(), SSLMode: q.Get("sslmode"),
		Internal: q.Get("internal") == "true",
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseInt(p, 10, 32)
		if err != nil {
			return capp.PostgresConfig{}, errPostgresDSN
		}
		c.Port = int32(n)
	}
	if ca := q.Get("sslrootcert"); ca != "" {
		b, err := os.ReadFile(ca) //nolint:gosec // G304: an operator's file, development only
		if err != nil {
			return capp.PostgresConfig{}, fmt.Errorf("dev seed: --postgres sslrootcert: %w", err)
		}
		c.CAPEM = string(b)
	}
	c.Tables = devPostgresTables()
	return c, nil
}

// devPostgresTables is the D19 fixture manifest.
func devPostgresTables() []capp.PostgresTable {
	col := func(n, t, c string) capp.PostgresColumn { return capp.PostgresColumn{Name: n, Type: t, Class: c} }
	return []capp.PostgresTable{
		{Schema: "shop", Name: "customers", ScopeKey: "customer", ScopeColumn: "id", Columns: []capp.PostgresColumn{
			col("id", "bigint", "public"), col("name", "text", "pii"), col("email", "text", "pii"), col("tier", "text", "public"),
			col("ssn", "text", "secret"),
		}},
		{Schema: "shop", Name: "orders", ScopeKey: "customer", ScopeColumn: "customer_id", Columns: []capp.PostgresColumn{
			col("id", "bigint", "public"), col("customer_id", "bigint", "public"), col("amount", "numeric", "internal"),
			col("status", "text", "public"),
		}},
		{Schema: "support", Name: "tickets", ScopeKey: "customer", ScopeColumn: "customer_id", Columns: []capp.PostgresColumn{
			col("id", "bigint", "public"), col("customer_id", "bigint", "public"), col("subject", "text", "internal"),
		}},
	}
}

// devPostgresPackage is pc.postgres for seedPackages.
func devPostgresPackage() devPackage {
	return devPackage{pcpostgres.Name, pcpostgres.Version, pcpostgres.Package}
}

// seedPostgresConnection creates the postgres connection "warehouse" to
// the --postgres database, in enforce mode, pantherclaw_held, through
// every connection check. DEVELOPMENT ONLY.
func seedPostgresConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, path string, stdout io.Writer) error {
	pc, err := devPostgresConfig(path)
	if err != nil {
		return err
	}
	class := capp.ClassPublic
	if pc.Internal {
		class = capp.ClassInternal
	}
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devPostgresConnectionName, Kind: capp.KindPostgres, Package: pcpostgres.Name, Gateway: gateway,
		DestinationClass: class, AccessMode: capp.AccessHeld, DefaultMode: "enforce", Postgres: &pc,
	})
	if err != nil {
		return fmt.Errorf("dev: postgres connection: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "seeded postgres connection %s (%s) to %s/%s as %s; confirm its manifest with your security key at "+
		"%s/connections/%s/postgres/confirm, seal the role's password with pclaw seal --connection %s --from-file PASSWORD.txt, "+
		"then test it with pclaw connection test %s --kind read; agents call the gateway at /mcp/%s or /%s/v1/query\n",
		c.ID, c.Name, pc.Host, pc.Database, pc.User, cfg.Auth.PublicURL, c.ID, c.ID, c.ID, c.Name, c.Name)
	return nil
}
