// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcpostgres "github.com/katocxl/pantherclaw/packages/pc-postgres"
)

// TestM14Data_PostgresConfigurationRoundTrip (G0 M14 D64): with the data
// wiring, a postgres connection can be created; its validated
// configuration is stored in pc.postgres_connections with its defaults,
// and loads back as the gateway's PostgresConfig.
func TestM14Data_PostgresConfigurationRoundTrip(t *testing.T) {
	d := dbtest.New(t)
	pool := d.AppPool(t)
	ctx := context.Background()
	org, gw := ids.New[ids.Org](), ids.NewV7()
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		pkg, ver := ids.NewV7(), ids.NewV7()
		raw := pcpostgres.Package
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'data')", []any{org}},
			{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", []any{org, gw}},
			{"INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, $3)", []any{org, pkg, pcpostgres.Name}},
			{`INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`,
				[]any{org, ver, pkg, pcpostgres.Version, manifest.FileDigest(raw), raw}},
			{"INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, $4, $5)",
				[]any{org, pkg, ver, pcpostgres.Version, manifest.FileDigest(raw)}},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	core := &m14Core{kinds: &ports.KindConfigs{}}
	wireM14Data(core)
	svc := capp.New(pool, nil, "https://pantherclaw.example.test", "https://gw.example.test").WithKindConfigs(core.kinds)
	in := capp.CreateInput{
		Name: "warehouse", Kind: capp.KindPostgres, Package: pcpostgres.Name, Gateway: gw, DestinationClass: capp.ClassPublic,
		AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		Postgres: &capp.PostgresConfig{Host: "db.example.test", Database: "shop", User: "reader", SSLMode: capp.SSLVerifyFull, Tables: devPostgresTables()},
	}
	c, err := svc.Seed(ctx, org, "test", in)
	if err != nil {
		t.Fatal(err)
	}
	var got proto.Message
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		got, err = postgresConfigs{}.Load(ctx, tx, org, c.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, ok := got.(*pb.PostgresConfig)
	if !ok || pc.GetHost() != "db.example.test" || pc.GetPort() != 5432 || pc.GetMaxRows() != 200 || pc.GetMinGroupSize() != 5 ||
		len(pc.GetTables()) != 3 || pc.GetTables()[0].GetColumns()[4].GetClass() != "secret" {
		t.Fatalf("loaded %v", got)
	}
	if err := (postgresConfigs{}).Save(ctx, db.TenantTx{}, org, c.ID, 1, "not a configuration"); err == nil {
		t.Fatal("saved another type")
	}
}
