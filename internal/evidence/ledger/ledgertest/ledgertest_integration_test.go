// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package ledgertest_test

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger/ledgertest"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestChainSettledWaitsForAnOpenTransaction: while a transaction that
// started earlier stays open, ledger.ChainAll links none of an org's
// committed entries (they sit above xmin), which is why a feed reader that
// chains once can read nothing; ChainSettled links them once the
// transaction ends (G0 M28 D719, the HR-687 drive).
// Covers: HR-687
func TestChainSettledWaitsForAnOpenTransaction(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	other := ids.New[ids.Org]()
	for _, o := range []ids.OrgID{org, other} {
		if err := p.InTenantTx(ctx, o, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", o)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Another org's transaction takes a transaction id and stays open.
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- p.InTenantTx(ctx, other, func(ctx context.Context, tx db.TenantTx) error {
			if _, err := tx.Exec(ctx, "SELECT pg_current_xact_id()"); err != nil {
				return err
			}
			close(started)
			<-release
			return nil
		})
	}()
	<-started

	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		body, err := domain.CanonicalBody(map[string]string{"k": "v"})
		if err != nil {
			return err
		}
		_, err = ledger.Append(ctx, tx, "test.appended", domain.Actor{Type: "system", ID: "test"}, body)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := ledger.ChainAll(ctx, p, org, 1000); err != nil || n != 0 {
		t.Fatalf("ChainAll under an open transaction linked %d (err %v), want 0", n, err)
	}

	go func() {
		time.Sleep(300 * time.Millisecond)
		close(release)
	}()
	if n := ledgertest.ChainSettled(t, ctx, p, org); n != 1 {
		t.Fatalf("ChainSettled linked %d, want 1", n)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
