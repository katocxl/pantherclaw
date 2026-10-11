// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestIntRefreshTrafficInventoriesChannels: the inventory records each
// channel and mode the gateway carried as an observed route of its scope,
// once, and leaves transactions younger than a minute for later.
func TestIntRefreshTrafficInventoriesChannels(t *testing.T) {
	f := newFixture(t)
	txn := func(channel, mode, age string) {
		f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, '\x0000000000000000000000000000000000000000000000000000000000000000',
			'github.pulls.merge', 'ALLOW', 'OK', 'gw', $5, $6, $7, now() - $8::interval)`,
			f.org, ids.NewV7(), f.run, ids.NewV7(), f.conn, channel, mode, age)
	}
	txn("mcp", "monitor", "10 minutes")
	txn("mcp", "enforce", "5 minutes")
	txn("http", "enforce", "2 minutes")
	txn("sdk", "enforce", "0 seconds")
	refresh := func() []domain.Scope {
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
	if s := refresh(); len(s) != 1 || s[0].Operation != "github.pulls.merge" || s[0].Agent != f.agent {
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
	if s := refresh(); len(s) != 0 {
		t.Fatalf("a second refresh found %v again", s)
	}
}
