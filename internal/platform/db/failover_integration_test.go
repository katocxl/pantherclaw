// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// TestHR496_PromotionHoldOnTheDatabase: on a real primary, the first start
// records the timeline; a timeline other than the acknowledged one (as
// after a promotion) holds with async, and with a declared sync that the
// primary does not confirm; bump-epochs' acknowledgement ends it; without
// the row the check fails closed (G0 M19 D207).
// Covers: PN-010.7
func TestHR496_PromotionHoldOnTheDatabase(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	app := d.AppPool(t)

	first, err := app.CheckPromotion(ctx, db.ReplicationAsync)
	if err != nil || first.Hold || first.Timeline < 1 || first.Acknowledged != 0 {
		t.Fatalf("first start = %+v, %v", first, err)
	}
	again, err := app.CheckPromotion(ctx, db.ReplicationAsync)
	if err != nil || again.Hold || again.Acknowledged != first.Timeline {
		t.Fatalf("second start = %+v, %v", again, err)
	}

	// A promotion, as the server sees it: the acknowledged timeline is
	// not the primary's.
	d.AdminExec(t, "UPDATE pc.db_primary_timeline SET timeline = $1", first.Timeline+7)
	for _, r := range []db.Replication{db.ReplicationAsync, db.ReplicationSync} {
		p, err := app.CheckPromotion(ctx, r)
		if err != nil || !p.Hold {
			t.Fatalf("%s after a promotion = %+v, %v, want the hold", r, p, err)
		}
		// The test cluster runs no synchronous standby, so a declared sync
		// is not confirmed.
		if r == db.ReplicationSync && !p.Unverified {
			t.Fatalf("declared sync on the test cluster counted as verified: %+v", p)
		}
	}
	if tl, err := app.AcknowledgeTimeline(ctx); err != nil || tl != first.Timeline {
		t.Fatalf("acknowledge = %d, %v", tl, err)
	}
	if p, err := app.CheckPromotion(ctx, db.ReplicationAsync); err != nil || p.Hold {
		t.Fatalf("after the acknowledgement = %+v, %v", p, err)
	}

	// Only purpose failover sees the row; pc_app cannot add or remove one.
	err = app.InTenantTx(ctx, createOrg(t, app, "failover-tenant"), func(ctx context.Context, tx db.TenantTx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM pc.db_primary_timeline").Scan(&n); err != nil || n != 0 {
			t.Errorf("tenant transaction sees %d rows (%v)", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{"INSERT INTO pc.db_primary_timeline (singleton) VALUES (true)", "DELETE FROM pc.db_primary_timeline"} {
		err := app.InGlobalTx(ctx, db.GlobalFailover, func(ctx context.Context, tx db.GlobalTx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		if err == nil {
			t.Errorf("pc_app ran %q", stmt)
		}
	}

	d.AdminExec(t, "DELETE FROM pc.db_primary_timeline")
	if _, err := app.CheckPromotion(ctx, db.ReplicationAsync); !errors.Is(err, db.ErrNoTimelineRow) {
		t.Fatalf("without the row: %v, want ErrNoTimelineRow", err)
	}
}
