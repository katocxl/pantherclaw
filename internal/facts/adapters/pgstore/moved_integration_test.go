// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgstore_test

import (
	"context"
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

// TestHR160_AGatewaysFactsCountOnlyWhileItServesTheConnection (#299
// review follow-up): a gateway provider's facts are read only while its
// gateway serves the connection and the connection is active, and a write
// checks that under a lock in its own transaction, so a report racing a
// move or a quarantine never lands, and what the old gateway reported
// stops counting at once, not when it ages out.
func TestHR160_AGatewaysFactsCountOnlyWhileItServesTheConnection(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	ctx := context.Background()
	org, alice, gw, other, conn := ids.New[ids.Org](), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", org, alice)
	exec("INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", org, gw)
	exec("INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", org, other)
	exec(`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, allowed_hosts, default_mode,
		created_by, updated_by) VALUES ($1, $2, 'github', 'http', $3, 'pc.github', 'https://api.github.com', 'pantherclaw_held',
		ARRAY['api.github.com'], 'enforce', 'test', 'test')`, org, conn, gw)
	named := func(context.Context, ids.OrgID, ids.UUID, ids.UUID) (map[string][]string, error) {
		return map[string][]string{"github.pull.head": {"github.pull_request"}}, nil
	}
	store := &pgstore.Store{Pool: p}
	svc := &app.Service{Store: store, Authz: allow{}, Packages: named}
	head := domain.Declaration{Name: "github.pull.head", Type: domain.TypeObject, SubjectType: "github.pull_request", MaxLag: time.Hour}
	prov, err := svc.RegisterGatewayProvider(as(org, tdomain.KindUser, alice), "github", gw, conn, []domain.Declaration{head})
	if err != nil {
		t.Fatal(err)
	}
	put := func(sha string) error {
		v, err := domain.DecodeValue(domain.TypeObject, []byte(`{"object":{"sha":"`+sha+`"}}`))
		if err != nil {
			t.Fatal(err)
		}
		// The observe time comes from the database clock, as Service.put
		// takes it (BUILD_GUIDE §3.1): the Go clock can run ahead of the
		// database's under load, and a fact observed after it is recorded
		// breaks facts_not_from_the_future.
		at, err := store.Now(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.Put(ctx, org, domain.Fact{
			Name: "github.pull.head", SubjectType: "github.pull_request", SubjectID: "acme/payments#7", ProviderID: prov.ID,
			Value: v, ObservedAt: at,
		})
		return err
	}
	read := func() bool {
		t.Helper()
		var facts map[string]domain.Fact
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			facts, err = store.Subject(ctx, dbq.New(tx), org, "github.pull_request", "acme/payments#7", []string{"github.pull.head"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		_, ok := facts["github.pull.head"]
		return ok
	}
	if err := put("aaaa"); err != nil || !read() {
		t.Fatalf("while it serves the connection: %v %v", err, read())
	}

	exec("UPDATE pc.connections SET gateway_id = $2 WHERE id = $1", conn, other)
	if read() {
		t.Fatal("the facts of a gateway the connection left still count")
	}
	if err := put("bbbb"); !errors.Is(err, app.ErrNotProvider) {
		t.Fatalf("a write after the move: %v", err)
	}

	exec("UPDATE pc.connections SET gateway_id = $2 WHERE id = $1", conn, gw)
	exec("UPDATE pc.connections SET state = 'QUARANTINED', quarantine_reason = 'test' WHERE id = $1", conn)
	if read() {
		t.Fatal("the facts of a quarantined connection still count")
	}
	if err := put("cccc"); !errors.Is(err, app.ErrNotProvider) {
		t.Fatalf("a write while quarantined: %v", err)
	}
}
