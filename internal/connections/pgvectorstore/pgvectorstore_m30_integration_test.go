// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgvectorstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgvectorstore"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	pcvectorstore "github.com/katocxl/pantherclaw/packages/pc-vectorstore"
)

func vectorConfig(writers ...ids.UUID) capp.VectorstoreConfig {
	return capp.VectorstoreConfig{
		Host: "vectors.example.test", Database: "rag", User: "writer", SSLMode: capp.SSLVerifyFull,
		Schema: "rag", Table: "docs", Dimensions: 3, Distance: "cosine", Writers: writers,
	}
}

// TestHR704_VectorstoreEndpointIsFixedAfterCreate: a vectorstore
// connection saves its endpoint and table, a change that keeps the
// endpoint applies, and one that moves it is VECTORSTORE_ENDPOINT_IMMUTABLE
// (G0 M30 D925a).
func TestHR704_VectorstoreEndpointIsFixedAfterCreate(t *testing.T) {
	f := triggerstest.New(t)
	gw, pkg, ver := ids.NewV7(), ids.NewV7(), ids.NewV7()
	raw := pcvectorstore.Package
	f.Exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", f.Org, gw)
	f.Exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, $3)", f.Org, pkg, pcvectorstore.Name)
	f.Exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`,
		f.Org, ver, pkg, pcvectorstore.Version, manifest.FileDigest(raw), raw)
	f.Exec(t, "INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, $4, $5)",
		f.Org, pkg, ver, pcvectorstore.Version, manifest.FileDigest(raw))
	kinds := &ports.KindConfigs{}
	kinds.Register(capp.KindVectorstore, pgvectorstore.Store{Hosted: func(ids.UUID) bool { return false }})
	conns := capp.New(f.Pool, nil, "https://pantherclaw.example.test", "https://gw.example.test").WithKindConfigs(kinds)
	admin := f.As(td.KindUser, td.RoleGatewayAdmin)

	writer := ids.NewV7()
	cfg := vectorConfig(writer)
	c, err := conns.Create(admin, capp.CreateInput{
		Name: "rag", Kind: capp.KindVectorstore, Package: pcvectorstore.Name, Gateway: gw, DestinationClass: capp.ClassInternal,
		AccessMode: capp.AccessHeld, DefaultMode: "enforce", Vectorstore: &cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := func() *pb.VectorstoreConfig {
		t.Helper()
		var out *pb.VectorstoreConfig
		f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
			m, err := pgvectorstore.Store{}.Load(ctx, tx, f.Org, c.ID)
			out, _ = m.(*pb.VectorstoreConfig)
			return err
		})
		return out
	}
	if s := served(); s.GetHost() != "vectors.example.test" || s.GetTableName() != "docs" || len(s.GetWriterAgentIds()) != 1 {
		t.Fatalf("served %v", s)
	}

	// Removing the writer narrows and keeps the endpoint: it applies.
	narrow := vectorConfig()
	if _, err := conns.Update(admin, capp.UpdateInput{ID: c.ID, Revision: c.Revision, Vectorstore: &narrow}); err != nil {
		t.Fatal(err)
	}
	if s := served(); len(s.GetWriterAgentIds()) != 0 {
		t.Fatalf("narrowed %v", s)
	}
	cur, err := conns.Get(admin, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	moved := vectorConfig()
	moved.Host = "elsewhere.example.test"
	if _, err := conns.Update(admin, capp.UpdateInput{ID: c.ID, Revision: cur.Revision, Vectorstore: &moved}); !errors.Is(err, capp.ErrVectorstoreEndpointImmutable) {
		t.Fatalf("moved endpoint: %v", err)
	}
	if s := served(); s.GetHost() != "vectors.example.test" {
		t.Fatalf("endpoint changed: %v", s)
	}
}
