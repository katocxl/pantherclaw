// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package a2astore_test

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

const peerCard = `{"name":"peer","description":"d","version":"1","capabilities":{},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],
	"supportedInterfaces":[{"url":"https://peer.example/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],
	"skills":[{"id":"refunds","name":"Refunds","description":"d","tags":["a"]},{"id":"wires","name":"Wires","description":"d","tags":["a"]}]}`

// TestHR590_TheServerSignsOnlyThePinnedCard (D232): the signature verifies
// under the published key for the card the server would rewrite itself; the
// key signs nothing else, for no other gateway, and no drifted pin.
// Covers: F882
func TestHR590_TheServerSignsOnlyThePinnedCard(t *testing.T) {
	pool := dbtest.New(t).AppPool(t)
	w := newWorld(t, pool, "https://peer.example/a2a")
	const url = "https://gw.example/a2a/peer"
	cfg := pinned(peerCard)
	cfg.PublicUrl = url
	w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		id, err := a2astore.Propose(ctx, q, w.org, w.conn, cfg, "user:x")
		if err != nil {
			return err
		}
		_, err = a2astore.ActivateAsOperator(ctx, q, w.org, w.conn, id, "test")
		return err
	})
	reg := keys.NewRegistry()
	k, err := keys.GenerateSigningKey(keys.PurposeA2ACard)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	s := &a2astore.CardSigner{Pool: pool, Keys: reg}
	ctx := context.Background()
	card, err := wire.Rewrite([]byte(peerCard), "JSONRPC", url, []string{"refunds"})
	if err != nil {
		t.Fatal(err)
	}
	signed, jwks, err := s.SignCard(ctx, w.org, w.gateway, w.conn, card)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := wire.ParseKeys(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifySignatures(signed, ks); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if _, ok := ks[k.KID]; !ok || len(ks) != 1 {
		t.Fatalf("keys: %v", ks)
	}

	allSkills, err := wire.Rewrite([]byte(peerCard), "JSONRPC", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath, err := wire.Rewrite([]byte(peerCard), "JSONRPC", "https://gw.example/a2a/other", []string{"refunds"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SignCard(ctx, w.org, w.gateway, w.conn, allSkills); !errors.Is(err, a2astore.ErrCardMismatch) {
		t.Errorf("a card with more skills: %v", err)
	}
	if _, _, err := s.SignCard(ctx, w.org, w.gateway, w.conn, wrongPath); !errors.Is(err, a2astore.ErrCardMismatch) {
		t.Errorf("another connection's path: %v", err)
	}
	if _, _, err := s.SignCard(ctx, w.org, w.gateway, w.conn, []byte(`{"not":"a card"}`)); !errors.Is(err, a2astore.ErrCardMismatch) {
		t.Errorf("not a card: %v", err)
	}
	if _, _, err := s.SignCard(ctx, w.org, ids.NewV7(), w.conn, card); !errors.Is(err, a2astore.ErrCardNotOurs) {
		t.Errorf("another gateway: %v", err)
	}
	if _, _, err := s.SignCard(ctx, w.org, w.gateway, ids.NewV7(), card); !errors.Is(err, a2astore.ErrCardNotOurs) {
		t.Errorf("another connection: %v", err)
	}
	if _, _, err := (&a2astore.CardSigner{Pool: pool, Keys: keys.NewRegistry()}).SignCard(ctx, w.org, w.gateway, w.conn, card); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Errorf("no key: %v", err)
	}
	w.tx(t, func(ctx context.Context, q *dbq.Queries, tx db.TenantTx) error {
		return (a2astore.DriftHook{}).Drift(ctx, tx, w.org, w.conn, hex.EncodeToString(cfg.GetCardDigest()), "unreadable")
	})
	if _, _, err := s.SignCard(ctx, w.org, w.gateway, w.conn, card); !errors.Is(err, a2astore.ErrCardDrifted) {
		t.Errorf("a drifted pin: %v", err)
	}
}

// TestD247_TheServerSignsOnlyTheStoredPublicURL: a gateway that serves the
// pinned card under its own host gets no signature, and a connection nobody
// gave a public URL gets none at all, so its card stays unsigned.
// Covers: F882
func TestD247_TheServerSignsOnlyTheStoredPublicURL(t *testing.T) {
	pool := dbtest.New(t).AppPool(t)
	pin := func(w world, public string) {
		cfg := pinned(peerCard)
		cfg.PublicUrl = public
		w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
			id, err := a2astore.Propose(ctx, q, w.org, w.conn, cfg, "user:x")
			if err != nil {
				return err
			}
			_, err = a2astore.ActivateAsOperator(ctx, q, w.org, w.conn, id, "test")
			return err
		})
	}
	reg := keys.NewRegistry()
	k, err := keys.GenerateSigningKey(keys.PurposeA2ACard)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	s := &a2astore.CardSigner{Pool: pool, Keys: reg}
	ctx := context.Background()
	const stored = "https://gw.example/a2a/peer"

	w := newWorld(t, pool, "https://peer.example/a2a")
	pin(w, stored)
	for _, host := range []string{"https://evil.example/a2a/peer", "https://gw.example.evil.example/a2a/peer"} {
		card, err := wire.Rewrite([]byte(peerCard), "JSONRPC", host, []string{"refunds"})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.SignCard(ctx, w.org, w.gateway, w.conn, card); !errors.Is(err, a2astore.ErrCardMismatch) {
			t.Errorf("%s: %v", host, err)
		}
	}
	got, err := func() (a2astore.Pin, error) {
		var p a2astore.Pin
		var err error
		w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
			p, err = a2astore.Get(ctx, q, w.org, w.conn, a2astore.StateActive)
			return err
		})
		return p, err
	}()
	if err != nil || got.Config.GetPublicUrl() != stored {
		t.Fatalf("stored: %q, %v", got.Config.GetPublicUrl(), err)
	}

	bare := newWorld(t, pool, "https://peer.example/a2a")
	pin(bare, "")
	card, err := wire.Rewrite([]byte(peerCard), "JSONRPC", stored, []string{"refunds"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SignCard(ctx, bare.org, bare.gateway, bare.conn, card); !errors.Is(err, a2astore.ErrCardNoPublicURL) {
		t.Errorf("no public URL: %v", err)
	}
}
