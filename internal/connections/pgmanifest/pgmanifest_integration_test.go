// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgmanifest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	pcpostgres "github.com/katocxl/pantherclaw/packages/pc-postgres"
)

func config() capp.PostgresConfig {
	return capp.PostgresConfig{
		Host: "db.example.test", Database: "shop", User: "reader", SSLMode: capp.SSLVerifyFull,
		Tables: []capp.PostgresTable{{Schema: "shop", Name: "customers", ScopeKey: "customer", ScopeColumn: "id", Columns: []capp.PostgresColumn{
			{Name: "id", Type: "bigint", Class: "public"}, {Name: "email", Type: "text", Class: "pii"}, {Name: "ssn", Type: "text", Class: "secret"},
		}}},
	}
}

// TestIntPostgresManifestConfirmation (G0 M14 D84, D92): a new postgres
// connection's configuration is proposed and the gateway gets none until a
// person with connection.manage confirms it with a fresh step-up; a
// narrowing change applies at once; a widening one waits while the
// confirmed configuration keeps serving, and a confirmation names the
// proposal it saw.
func TestIntPostgresManifestConfirmation(t *testing.T) {
	f := triggerstest.New(t)
	gw, pkg, ver := ids.NewV7(), ids.NewV7(), ids.NewV7()
	raw := pcpostgres.Package
	f.Exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", f.Org, gw)
	f.Exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, $3)", f.Org, pkg, pcpostgres.Name)
	f.Exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`,
		f.Org, ver, pkg, pcpostgres.Version, manifest.FileDigest(raw), raw)
	f.Exec(t, "INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, $4, $5)",
		f.Org, pkg, ver, pcpostgres.Version, manifest.FileDigest(raw))
	kinds := &ports.KindConfigs{}
	kinds.Register(capp.KindPostgres, pgmanifest.Store{})
	conns := capp.New(f.Pool, nil, "https://pantherclaw.example.test", "https://gw.example.test").WithKindConfigs(kinds)
	svc := pgmanifest.New(f.Pool)
	admin := f.As(td.KindUser, td.RoleGatewayAdmin)
	fresh := func() *stepup.StepUp { return &stepup.StepUp{Credential: f.Cred, At: time.Now()} }

	cfg := config()
	c, err := conns.Create(admin, capp.CreateInput{
		Name: "warehouse", Kind: capp.KindPostgres, Package: pcpostgres.Name, Gateway: gw, DestinationClass: capp.ClassPublic,
		AccessMode: capp.AccessHeld, DefaultMode: "enforce", Postgres: &cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := func() *pb.PostgresConfig {
		t.Helper()
		var out *pb.PostgresConfig
		f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
			m, err := pgmanifest.Store{}.Load(ctx, tx, f.Org, c.ID)
			out, _ = m.(*pb.PostgresConfig)
			return err
		})
		return out
	}
	if served() != nil {
		t.Fatal("an unconfirmed configuration is served")
	}
	m, err := svc.Get(admin, c.ID)
	if err != nil || m.Current != nil || m.Proposed == nil || len(m.Widening) != 1 || m.Digest == "" {
		t.Fatalf("get: %+v %v", m, err)
	}
	if err := svc.Confirm(admin, c.ID, m.Digest, nil); !stepup.Is(err) {
		t.Fatalf("no step-up: %v", err)
	}
	if err := svc.Confirm(admin, c.ID, m.Digest, &stepup.StepUp{Credential: f.Cred, At: time.Now().Add(-10 * time.Minute)}); !stepup.Is(err) {
		t.Fatalf("stale step-up: %v", err)
	}
	if err := svc.Confirm(f.As(td.KindUser, td.RoleOrgAdmin), c.ID, m.Digest, fresh()); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("without connection.manage: %v", err)
	}
	if err := svc.Confirm(admin, c.ID, "00"+m.Digest[2:], fresh()); !errors.Is(err, pgmanifest.ErrChanged) {
		t.Fatalf("another digest: %v", err)
	}
	if err := svc.Confirm(admin, c.ID, m.Digest, fresh()); err != nil {
		t.Fatal(err)
	}
	if s := served(); s == nil || len(s.GetTables()[0].GetColumns()) != 3 || s.GetMaxRows() != capp.DefaultPostgresMaxRows {
		t.Fatalf("confirmed: %v", s)
	}
	if err := svc.Confirm(admin, c.ID, m.Digest, fresh()); !errors.Is(err, pgmanifest.ErrNothing) {
		t.Fatalf("again: %v", err)
	}

	// Narrowing applies at once.
	narrow := config()
	narrow.Tables[0].Columns = narrow.Tables[0].Columns[:2]
	narrow.MaxRows = 50
	u, err := conns.Update(admin, capp.UpdateInput{ID: c.ID, Revision: c.Revision, Postgres: &narrow})
	if err != nil {
		t.Fatal(err)
	}
	if s := served(); len(s.GetTables()[0].GetColumns()) != 2 || s.GetMaxRows() != 50 {
		t.Fatalf("narrowed: %v", s)
	}

	// Widening waits; the narrowed configuration keeps serving.
	wide := config()
	wide.Tables[0].Columns[1].Class = "public"
	wide.Internal = true
	u, err = conns.Update(admin, capp.UpdateInput{ID: c.ID, Revision: u.Revision, Postgres: &wide})
	if err != nil {
		t.Fatal(err)
	}
	if s := served(); len(s.GetTables()[0].GetColumns()) != 2 || s.GetInternal() {
		t.Fatalf("a widening applied: %v", s)
	}
	m, err = svc.Get(admin, c.ID)
	if err != nil || m.Current == nil || m.Proposed == nil || len(m.Widening) < 3 {
		t.Fatalf("proposal: %+v %v", m.Widening, err)
	}
	if err := svc.Confirm(admin, c.ID, m.Digest, fresh()); err != nil {
		t.Fatal(err)
	}
	if s := served(); !s.GetInternal() || s.GetTables()[0].GetColumns()[1].GetClass() != "public" {
		t.Fatalf("widened: %v", s)
	}

	// A narrowing change voids a pending widening.
	wider := config()
	wider.Internal = true
	wider.MaxRows = 1000
	u, err = conns.Update(admin, capp.UpdateInput{ID: c.ID, Revision: u.Revision, Postgres: &wider})
	if err != nil {
		t.Fatal(err)
	}
	narrower := config()
	narrower.Internal = true
	narrower.Tables[0].Columns = narrower.Tables[0].Columns[:1]
	if _, err := conns.Update(admin, capp.UpdateInput{ID: c.ID, Revision: u.Revision, Postgres: &narrower}); err != nil {
		t.Fatal(err)
	}
	if m, err := svc.Get(admin, c.ID); err != nil || m.Proposed != nil || len(m.Current.Tables[0].Columns) != 1 {
		t.Fatalf("voided: %+v %v", m, err)
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.connection.postgres_manifest_confirmed'"); n != 2 {
		t.Fatalf("%d confirmations audited", n)
	}
}

// TestIntPostgresInternalOnlyOnCustomerHostedGateways (D98, HR-077): a
// connection a PantherClaw-hosted gateway serves cannot be internal,
// neither at creation nor by an update; on a customer-hosted gateway it can.
func TestIntPostgresInternalOnlyOnCustomerHostedGateways(t *testing.T) {
	f := triggerstest.New(t)
	hosted, own, pkg, ver := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	raw := pcpostgres.Package
	f.Exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'hosted', 'test')", f.Org, hosted)
	f.Exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'own', 'test')", f.Org, own)
	f.Exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, $3)", f.Org, pkg, pcpostgres.Name)
	f.Exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`,
		f.Org, ver, pkg, pcpostgres.Version, manifest.FileDigest(raw), raw)
	f.Exec(t, "INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, $4, $5)",
		f.Org, pkg, ver, pcpostgres.Version, manifest.FileDigest(raw))
	kinds := &ports.KindConfigs{}
	kinds.Register(capp.KindPostgres, pgmanifest.Store{Hosted: func(g ids.UUID) bool { return g == hosted }})
	conns := capp.New(f.Pool, nil, "https://pantherclaw.example.test", "https://gw.example.test").WithKindConfigs(kinds)
	admin := f.As(td.KindUser, td.RoleGatewayAdmin)
	in := func(name string, gw ids.UUID, internal bool) capp.CreateInput {
		cfg := config()
		cfg.Internal = internal
		return capp.CreateInput{
			Name: name, Kind: capp.KindPostgres, Package: pcpostgres.Name, Gateway: gw, DestinationClass: capp.ClassInternal,
			AccessMode: capp.AccessHeld, DefaultMode: "enforce", Postgres: &cfg,
		}
	}
	if _, err := conns.Create(admin, in("hosted-internal", hosted, true)); !errors.Is(err, pgmanifest.ErrInternalHosted) {
		t.Fatalf("internal on a hosted gateway: %v", err)
	}
	c, err := conns.Create(admin, in("hosted-public", hosted, false))
	if err != nil {
		t.Fatal(err)
	}
	wide := config()
	wide.Internal = true
	if _, err := conns.Update(admin, capp.UpdateInput{ID: c.ID, Revision: c.Revision, Postgres: &wide}); !errors.Is(err, pgmanifest.ErrInternalHosted) {
		t.Fatalf("internal by update on a hosted gateway: %v", err)
	}
	owned, err := conns.Create(admin, in("own-internal", own, true))
	if err != nil {
		t.Fatalf("internal on a customer-hosted gateway: %v", err)
	}
	// An internal connection cannot move to a gateway PantherClaw hosts (D105).
	if _, err := conns.Update(admin, capp.UpdateInput{ID: owned.ID, Revision: owned.Revision, Gateway: &hosted}); !errors.Is(err, pgmanifest.ErrInternalHosted) {
		t.Fatalf("an internal connection moved to a hosted gateway: %v", err)
	}
	if _, err := conns.Update(admin, capp.UpdateInput{ID: c.ID, Revision: c.Revision, Gateway: &own}); err != nil {
		t.Fatalf("a public connection moving gateway: %v", err)
	}
	// The confirm page checks the gateway serving it now (D105): here the
	// gateway became one PantherClaw hosts after the proposal.
	svc := pgmanifest.New(f.Pool)
	svc.Hosted = func(g ids.UUID) bool { return g == own }
	m, err := svc.Get(admin, owned.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Confirm(admin, owned.ID, m.Digest, &stepup.StepUp{Credential: f.Cred, At: time.Now()}); !errors.Is(err, pgmanifest.ErrInternalHosted) {
		t.Fatalf("confirm on a now hosted gateway: %v", err)
	}
}
