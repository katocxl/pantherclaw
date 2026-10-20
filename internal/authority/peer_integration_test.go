// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR324_PeerCheckAsksOnlyAboutPeers (D89, D103): the decision-time
// peer check refuses a grant that cannot delegate only for a connection
// naming a peer agent of the org; a connection to an external peer, or one
// without a confirmed card, is no delegation to check (the latter refused
// as unconfirmed).
func TestHR324_PeerCheckAsksOnlyAboutPeers(t *testing.T) {
	pool := dbtest.New(t).AppPool(t)
	org, gw, agent := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	external, enrolled, unconfirmed := ids.NewV7(), ids.NewV7(), ids.NewV7()
	tx := func(fn func(ctx context.Context, q *dbq.Queries, tx db.TenantTx) error) {
		t.Helper()
		if err := pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			return fn(ctx, dbq.New(tx), tx)
		}); err != nil {
			t.Fatal(err)
		}
	}
	tx(func(ctx context.Context, q *dbq.Queries, tx db.TenantTx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'peer-check')", []any{org}},
			{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", []any{org, gw}},
			{"INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'peer', 'DISCOVERED', 'test')", []any{org, agent}},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		for i, c := range []ids.UUID{external, enrolled, unconfirmed} {
			if _, err := tx.Exec(ctx, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, simulated, created_by, updated_by)
				VALUES ($1, $2, $3, 'a2a', $4, 'pc.a2a', 'https://peer.example/a2a', 'pantherclaw_held', true, 'test', 'test')`,
				org, c, []string{"ext", "enr", "unc"}[i], gw); err != nil {
				return err
			}
		}
		for _, c := range []ids.UUID{external, enrolled} {
			d := sha256.Sum256([]byte(c.String()))
			cfg := &pb.A2AConfig{
				CardUrl: "https://peer.example/.well-known/agent-card.json", PinnedCard: []byte(`{"name":"p"}`), CardDigest: d[:],
				Interface: &pb.A2AInterface{Protocol: "JSONRPC", Url: "https://peer.example/a2a"}, MaxAnswerBytes: 1 << 20, MaxStreamSeconds: 300,
			}
			if c == enrolled {
				cfg.PeerAgentId, cfg.PeerScope = agent.String(), &pb.A2APeerScope{Bounds: []byte(`{}`)}
			}
			id, err := a2astore.Propose(ctx, q, org, c, cfg, "test")
			if err != nil {
				return err
			}
			if _, err := a2astore.ActivateAsOperator(ctx, q, org, c, id, "test"); err != nil {
				return err
			}
		}
		return nil
	})
	p := &authority.Peer{Pool: pool}
	cannot := gdomain.Grant{Delegation: gdomain.Delegation{Depth: 0, MaxChildren: 5}}
	can := gdomain.Grant{Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5}}
	none := gdomain.Grant{Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 0}}
	for name, c := range map[string]struct {
		conn   ids.UUID
		grant  gdomain.Grant
		refuse bool
	}{
		"external peer, grant cannot delegate": {external, cannot, false},
		"enrolled peer, grant cannot delegate": {enrolled, cannot, true},
		"enrolled peer, no children allowed":   {enrolled, none, true},
		"enrolled peer, grant delegates":       {enrolled, can, false},
		"no confirmed card":                    {unconfirmed, can, true},
	} {
		got := p.Check(context.Background(), org, pipeline.Connection{ID: c.conn, Kind: "a2a"}, c.grant)
		if (got != "") != c.refuse {
			t.Errorf("%s: %q", name, got)
		}
	}
}
