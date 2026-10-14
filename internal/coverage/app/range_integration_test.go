// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR222_SimulatedTrafficNeverReachesCoverage (D6): the traffic
// inventory skips a range run's transactions, so a channel only a range run
// used is no observed route; and the connections coverage snapshots cover
// never include a simulated one.
func TestHR222_SimulatedTrafficNeverReachesCoverage(t *testing.T) {
	f := newFixture(t)
	f.txn(t, ids.NewV7(), "mcp", "enforce", "10 minutes")
	// A range run's transaction on an http channel nobody else used.
	sim := ids.NewV7()
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, simulated, created_at) VALUES ($1, $2, $3, $4,
		'\x0000000000000000000000000000000000000000000000000000000000000000', 'github.pulls.merge', 'ALLOW', 'OK', 'gw', $5,
		'http', 'enforce', true, now() - interval '10 minutes')`, f.org, sim, f.run, ids.NewV7(), f.conn)
	if s := f.refresh(t); len(s) != 1 {
		t.Fatalf("scopes %v, want the real transaction's only", s)
	}
	routes, _, err := f.svc.ListRoutes(f.as(td.RoleAuditor), app.Filter{Connection: &f.conn}, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if r.Channel != nil && *r.Channel == "http" {
			t.Fatalf("a range run's channel became an observed route: %+v", r)
		}
	}
	if n := f.count(t, "SELECT count(*) FROM pc.coverage_invalidations WHERE kind = 'route'"); n != 1 {
		t.Fatalf("%d route changes, want one (the real mcp route)", n)
	}

	// Snapshot candidates: the real connection, never a simulated one.
	simConn := ids.NewV7()
	f.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
		created_by, updated_by, simulated) VALUES ($1, $2, 'payments-sim', 'http', $3, 'pc.mock-payments', 'http://127.0.0.1:9000',
		'none', 'enforce', 'test', 'test', true)`, f.org, simConn, f.gateway)
	var got []ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).CoverageConnectionPackages(ctx, f.org)
		for _, r := range rows {
			got = append(got, r.ID)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != f.conn {
		t.Fatalf("snapshot candidates %v, want only %s", got, f.conn)
	}
}
