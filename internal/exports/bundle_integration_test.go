// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exports

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

type fakeBundles struct {
	sel    evapp.Selection
	caller tenancy.Caller
}

var bundleBody = []byte(`{"format":"pantherclaw.bundle/v1"}`)

func (f *fakeBundles) ExportBundle(ctx context.Context, sel evapp.Selection, _ uint64) (evapp.Export, error) {
	f.sel = sel
	c, err := tenancy.CallerFrom(ctx)
	f.caller = c
	return evapp.Export{Bundle: bundleBody}, err
}

// TestHR515_ABundleWhoseEvidenceIsRemovedGetsANotice: a proof bundle is
// built as the person who asked, and when retention removes a ledger body
// in its range the destination gets the notice; a body outside the range
// changes nothing.
// Covers: F517
func TestHR515_ABundleWhoseEvidenceIsRemovedGetsANotice(t *testing.T) {
	f := newPushFixture(t)
	bundles := &fakeBundles{}
	f.svc.bundles = bundles
	dest := f.destination(t, "vault", ClassProofBundles)
	r, err := f.svc.Push(f.admin, PushRequest{Destination: dest, Class: ClassProofBundles, FromSeq: 10, ToSeq: 20})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.svc.Run(ctx, f.org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	got := f.receipt(t, r.ID)
	if got.State != ReceiptDelivered || bundles.sel.From != 10 || bundles.sel.To != 20 || bundles.caller.Principal.ID != f.user {
		t.Fatalf("receipt %+v, selection %+v", got, bundles.sel)
	}
	if b, _ := f.sim.object("bkt/" + got.ObjectKey); !bytes.Equal(b, bundleBody) {
		t.Fatalf("object %q", b)
	}
	removed := func(seq int64) {
		t.Helper()
		entry := ids.NewV7()
		f.d.AdminDo(t, func(c *pgx.Conn) error {
			tx, err := c.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body, body_removed_at, removed_by_policy)
				VALUES ($1, $2, 'audit.test', 'system', 'test', NULL, now(), $3)`, f.org, entry, ids.NewV7()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO pc.ledger_chain (org_id, seq, entry_id, prev_hash, entry_hash) VALUES ($1, $2, $3, $4, $4)`,
				f.org, seq, entry, bytes.Repeat([]byte{1}, 32)); err != nil {
				return err
			}
			return tx.Commit(ctx)
		})
	}
	removed(9)
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.RemovedHereAt != nil {
		t.Fatalf("a body outside the range: %+v", got)
	}
	removed(15)
	if err := f.svc.Sweep(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if got := f.receipt(t, r.ID); got.NoticeState != "SENT" || got.Status != "removed here; a copy exists at vault" {
		t.Fatalf("after removal: %+v", got)
	}
}
