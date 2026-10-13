// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgstore_test

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR160_AGatewayReportsOnlyItsConnectionsDeclaredFacts: a person
// registers the gateway serving a connection as the provider of facts its
// package names; only that gateway may report them, only those facts, and
// an object fact is stored and read back whole (G0 M8 decision 5). A fact
// may be named for several target types. Once the connection moves to
// another gateway or is quarantined, its old gateway reports nothing, and a
// fact the pinned package no longer names is refused.
func TestHR160_AGatewayReportsOnlyItsConnectionsDeclaredFacts(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	ctx := context.Background()
	org, alice, gw, other, conn := ids.New[ids.Org](), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", []any{org}},
			{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", []any{org, alice}},
			{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", []any{org, gw}},
			{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", []any{org, other}},
			{`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, allowed_hosts, default_mode,
				created_by, updated_by) VALUES ($1, $2, 'github', 'http', $3, 'pc.github', 'https://api.github.com', 'pantherclaw_held',
				ARRAY['api.github.com'], 'enforce', 'test', 'test')`, []any{org, conn, gw}},
		} {
			if _, err := tx.Exec(ctx, stmt.sql, stmt.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pinned := map[string][]string{"github.pull.head": {"github.repository", "github.pull_request"}}
	named := func(_ context.Context, _ ids.OrgID, g, c ids.UUID) (map[string][]string, error) {
		if g != gw || c != conn {
			return nil, app.ErrConnectionUnknown
		}
		return pinned, nil
	}
	svc := &app.Service{Store: &pgstore.Store{Pool: p}, Authz: allow{}, Packages: named}
	human := as(org, tdomain.KindUser, alice)
	head := domain.Declaration{Name: "github.pull.head", Type: domain.TypeObject, SubjectType: "github.pull_request", MaxLag: time.Minute}
	for name, d := range map[string]domain.Declaration{
		"a fact the package does not name": {Name: "github.pull.secret", Type: domain.TypeObject, SubjectType: "github.pull_request", MaxLag: time.Minute},
		"another subject":                  {Name: "github.pull.head", Type: domain.TypeObject, SubjectType: "github.branch", MaxLag: time.Minute},
	} {
		if _, err := svc.RegisterGatewayProvider(human, "github", gw, conn, []domain.Declaration{d}); !errors.Is(err, app.ErrNotDeclared) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := svc.RegisterGatewayProvider(human, "github", other, conn, []domain.Declaration{head}); !errors.Is(err, app.ErrConnectionUnknown) {
		t.Fatalf("a gateway that does not serve the connection: %v", err)
	}
	if _, err := svc.RegisterGatewayProvider(as(org, tdomain.KindServiceAccount, ids.NewV7()), "github", gw, conn, []domain.Declaration{head}); !errors.Is(err, app.ErrHumanOnly) {
		t.Fatalf("a service account registered a gateway provider: %v", err)
	}
	prov, err := svc.RegisterGatewayProvider(human, "github", gw, conn, []domain.Declaration{head})
	if err != nil {
		t.Fatal(err)
	}
	if prov.GatewayID != gw || prov.ConnectionID != conn || !prov.ServiceAccountID.IsZero() {
		t.Fatalf("provider %+v", prov)
	}

	now := time.Now().UTC()
	value := jsontext.Value(`{"object":{"sha":"0123456789abcdef0123456789abcdef01234567","base":"main","draft":false,"changed_files":2}}`)
	o := domain.Observation{Name: "github.pull.head", SubjectType: "github.pull_request", SubjectID: "acme/payments#7", Value: value, ObservedAt: now}
	if _, err := svc.PutGatewayFacts(ctx, org, other, conn, []domain.Observation{o}); !errors.Is(err, app.ErrNotProvider) {
		t.Fatalf("another gateway reported: %v", err)
	}
	res, err := svc.PutGatewayFacts(ctx, org, gw, conn, []domain.Observation{o, {
		Name: "github.pull.secret", SubjectType: "github.pull_request", SubjectID: "acme/payments#7", Value: value, ObservedAt: now,
	}})
	if err != nil || res[0].Err != nil || !errors.Is(res[1].Err, domain.ErrUntrusted) {
		t.Fatalf("report: %v %+v", err, res)
	}
	var facts map[string]domain.Fact
	err = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		facts, err = (&pgstore.Store{Pool: p}).Subject(ctx, dbq.New(tx), org, "github.pull_request", "acme/payments#7", []string{"github.pull.head"})
		return err
	})
	if f := facts["github.pull.head"]; err != nil || f.Value.Object["base"] != "main" || f.Value.Object["changed_files"] != int64(2) {
		t.Fatalf("read back %+v %v", facts, err)
	}

	exec := func(sql string, args ...any) {
		t.Helper()
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// The pin changed and no longer names the fact: refused like an
	// undeclared one.
	pinned = map[string][]string{"github.pull.head": {"github.repository"}}
	if res, err := svc.PutGatewayFacts(ctx, org, gw, conn, []domain.Observation{o}); err != nil || !errors.Is(res[0].Err, domain.ErrUntrusted) {
		t.Fatalf("a fact the pin no longer names: %v %+v", err, res)
	}
	pinned = map[string][]string{"github.pull.head": {"github.pull_request"}}
	exec("UPDATE pc.connections SET state = 'QUARANTINED', quarantine_reason = 'test' WHERE id = $1", conn)
	if _, err := svc.PutGatewayFacts(ctx, org, gw, conn, []domain.Observation{o}); !errors.Is(err, app.ErrNotProvider) {
		t.Fatalf("a quarantined connection's gateway reported: %v", err)
	}
	exec("UPDATE pc.connections SET state = 'ACTIVE', quarantine_reason = NULL, gateway_id = $2 WHERE id = $1", conn, other)
	for _, g := range []ids.UUID{gw, other} {
		if _, err := svc.PutGatewayFacts(ctx, org, g, conn, []domain.Observation{o}); !errors.Is(err, app.ErrNotProvider) {
			t.Fatalf("gateway %s reported for a connection that moved: %v", g, err)
		}
	}
}
