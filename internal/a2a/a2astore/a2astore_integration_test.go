// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package a2astore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type world struct {
	pool *db.Pool
	org  ids.OrgID
	conn ids.UUID
}

func newWorld(t *testing.T, pool *db.Pool) world {
	t.Helper()
	w := world{pool: pool, org: ids.New[ids.Org](), conn: ids.NewV7()}
	gw := ids.NewV7()
	w.tx(t, func(ctx context.Context, q *dbq.Queries, tx db.TenantTx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'a2a')", []any{w.org}},
			{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", []any{w.org, gw}},
			{`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, created_by, updated_by)
				VALUES ($1, $2, 'peer', 'a2a', $3, 'pc.a2a', 'https://peer.example/a2a', 'pantherclaw_held', 'test', 'test')`, []any{w.org, w.conn, gw}},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		return nil
	})
	return w
}

func (w world) tx(t *testing.T, fn func(ctx context.Context, q *dbq.Queries, tx db.TenantTx) error) {
	t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, dbq.New(tx), tx)
	}); err != nil {
		t.Fatal(err)
	}
}

func config(card string) *pb.A2AConfig {
	d := sha256.Sum256([]byte(card))
	return &pb.A2AConfig{
		CardUrl: "https://peer.example/.well-known/agent-card.json", PinnedCard: []byte(card), CardDigest: d[:],
		Interface: &pb.A2AInterface{Protocol: "JSONRPC", Url: "https://peer.example/a2a"}, Skills: []string{"refunds"},
		MaxAnswerBytes: 1 << 20, MaxStreamSeconds: 300,
	}
}

// TestHR322_StoredPinRoundTripsAndDriftClearsOnRepin (G0 M14 D30, D64):
// a pin is stored and loaded as pinned; drift is recorded once against the
// pinned digest; a new pin clears it; another org sees nothing (RLS); and
// an unpinned configuration is never stored.
func TestHR322_StoredPinRoundTripsAndDriftClearsOnRepin(t *testing.T) {
	d := dbtest.New(t)
	pool := d.AppPool(t)
	w := newWorld(t, pool)
	cfg := config(`{"name":"peer"}`)
	w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		if err := a2astore.Insert(ctx, q, w.org, w.conn, &pb.A2AConfig{CardUrl: cfg.CardUrl, Interface: cfg.Interface}, "user:x"); !errors.Is(err, a2astore.ErrUnpinned) {
			t.Fatalf("unpinned insert: %v", err)
		}
		return a2astore.Insert(ctx, q, w.org, w.conn, cfg, "user:admin")
	})
	w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		p, err := a2astore.Load(ctx, q, w.org, w.conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(p.Config.GetPinnedCard(), cfg.GetPinnedCard()) || !bytes.Equal(p.Config.GetCardDigest(), cfg.GetCardDigest()) ||
			p.Config.GetInterface().GetUrl() != cfg.GetInterface().GetUrl() || p.PinnedBy != "user:admin" || p.DriftedAt != nil {
			t.Fatalf("loaded %+v", p)
		}
		observed := sha256.Sum256([]byte("other"))
		if ok, err := a2astore.MarkDrift(ctx, q, w.org, w.conn, cfg.GetCardDigest(), observed[:]); err != nil || !ok {
			t.Fatalf("drift: %v %v", ok, err)
		}
		if ok, _ := a2astore.MarkDrift(ctx, q, w.org, w.conn, cfg.GetCardDigest(), observed[:]); ok {
			t.Fatal("drift recorded twice")
		}
		stale := sha256.Sum256([]byte("stale"))
		if ok, _ := a2astore.MarkDrift(ctx, q, w.org, w.conn, stale[:], observed[:]); ok {
			t.Fatal("drift against a digest that is not the pin")
		}
		return nil
	})
	repinned := config(`{"name":"peer","version":"2"}`)
	w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		if err := a2astore.Replace(ctx, q, w.org, w.conn, repinned, "user:admin"); err != nil {
			return err
		}
		p, err := a2astore.Load(ctx, q, w.org, w.conn)
		if err != nil {
			return err
		}
		if p.DriftedAt != nil || p.Observed != nil || !bytes.Equal(p.Config.GetCardDigest(), repinned.GetCardDigest()) {
			t.Fatalf("after re-pin: %+v", p)
		}
		return nil
	})
	other := newWorld(t, pool)
	other.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		if _, err := a2astore.Load(ctx, q, other.org, w.conn); !errors.Is(err, a2astore.ErrNotFound) {
			t.Fatalf("another org reads the pin: %v", err)
		}
		if _, err := a2astore.Load(ctx, q, w.org, w.conn); !errors.Is(err, a2astore.ErrNotFound) {
			t.Fatalf("RLS lets another org's transaction read the pin: %v", err)
		}
		return nil
	})
}
