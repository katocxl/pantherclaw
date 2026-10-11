// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// txn records a gateway transaction of the fixture's scope with id,
// created age ago.
func (f *fixture) txn(t *testing.T, id ids.UUID, channel, mode, age string) {
	t.Helper()
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, '\x0000000000000000000000000000000000000000000000000000000000000000',
		'github.pulls.merge', 'ALLOW', 'OK', 'gw', $5, $6, $7, now() - $8::interval)`,
		f.org, id, f.run, ids.NewV7(), f.conn, channel, mode, age)
}

func (f *fixture) refresh(t *testing.T) []domain.Scope {
	t.Helper()
	var scopes []domain.Scope
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		scopes, err = f.svc.RefreshTraffic(ctx, tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return scopes
}

// v7At is a UUIDv7 of the time at.
func v7At(at time.Time) ids.UUID {
	u, ms := ids.NewV7(), uint64(at.UnixMilli())
	for i := range 6 {
		u[i] = byte(ms >> (40 - 8*i))
	}
	return u
}

// TestIntRefreshTrafficInventoriesChannels: the inventory records each
// channel and mode the gateway carried as an observed route of its scope,
// once, with a route change for each first sighting, and leaves
// transactions younger than a minute for later.
func TestIntRefreshTrafficInventoriesChannels(t *testing.T) {
	f := newFixture(t)
	f.txn(t, ids.NewV7(), "mcp", "monitor", "10 minutes")
	f.txn(t, ids.NewV7(), "mcp", "enforce", "5 minutes")
	f.txn(t, ids.NewV7(), "http", "enforce", "2 minutes")
	f.txn(t, ids.NewV7(), "sdk", "enforce", "0 seconds")
	if s := f.refresh(t); len(s) != 1 || s[0].Operation != "github.pulls.merge" || s[0].Agent != f.agent {
		t.Fatalf("scopes %v", s)
	}
	routes, _, err := f.svc.ListRoutes(f.as(td.RoleAuditor), app.Filter{Connection: &f.conn}, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range routes {
		got[*r.Channel] = *r.Mode
	}
	if len(got) != 2 || got["mcp"] != "enforce" || got["http"] != "enforce" {
		t.Fatalf("channel routes %v; the sdk call is younger than a minute", got)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.coverage_invalidations WHERE kind = 'route'"); n != 2 {
		t.Fatalf("%d route changes, want one per new route", n)
	}
	if s := f.refresh(t); len(s) != 0 {
		t.Fatalf("a second refresh found %v again", s)
	}
}

// TestIntRefreshTrafficCatchesLateCommits: a transaction whose id is older
// than the watermark (it committed late) is still inventoried, once; the
// transactions read again in the overlap change nothing.
func TestIntRefreshTrafficCatchesLateCommits(t *testing.T) {
	f := newFixture(t)
	f.txn(t, ids.NewV7(), "http", "enforce", "2 minutes")
	if s := f.refresh(t); len(s) != 1 {
		t.Fatalf("scopes %v", s)
	}
	f.txn(t, v7At(time.Now().Add(-3*time.Minute)), "mcp", "enforce", "2 minutes")
	if s := f.refresh(t); len(s) != 1 {
		t.Fatalf("the late transaction: scopes %v", s)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.coverage_routes WHERE channel = 'mcp' AND seen_count = 1"); n != 1 {
		t.Fatalf("%d late routes", n)
	}
	if s := f.refresh(t); len(s) != 0 {
		t.Fatalf("the overlap read again: %v", s)
	}
	if n := f.count(t, "SELECT sum(seen_count) FROM pc.coverage_routes"); n != 2 {
		t.Fatalf("%d sightings, want each transaction counted once", n)
	}
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}
