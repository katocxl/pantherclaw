// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

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
	if tl, err := app.AcknowledgeTimeline(ctx, db.ReplicationAsync); err != nil || tl != first.Timeline {
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

// TestHR496_TheRunningPathReadsTheAcknowledgedRow: a process that verified
// sync at start accepts a verified new primary only while the row still
// says sync was verified on the acknowledged timeline; a later start may
// have cleared it, and that process's memory does not count (G0 M19 D221).
// Covers: PN-010.7
func TestHR496_TheRunningPathReadsTheAcknowledgedRow(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	row := func() (timeline int64, verified bool) {
		d.AdminQueryRow(t, "SELECT timeline, sync_verified FROM pc.db_primary_timeline", nil, &timeline, &verified)
		return timeline, verified
	}

	d.AdminExec(t, "UPDATE pc.db_primary_timeline SET timeline = 7, sync_verified = false")
	app := d.AppPool(t)
	if err := db.PromoteForTest(ctx, app, 7, 8); !errors.Is(err, db.ErrTimelineChanged) {
		t.Fatalf("row not verified: %v, want refused", err)
	}
	if !app.TimelineChanged() {
		t.Fatal("the pool serves after a refused promotion")
	}
	if tl, verified := row(); tl != 7 || verified {
		t.Fatalf("a refused promotion wrote the row: %d %v", tl, verified)
	}

	d.AdminExec(t, "UPDATE pc.db_primary_timeline SET sync_verified = true")
	app = d.AppPool(t)
	if err := db.PromoteForTest(ctx, app, 7, 8); err != nil || app.TimelineChanged() {
		t.Fatalf("row verified: %v changed=%v", err, app.TimelineChanged())
	}
	if tl, verified := row(); tl != 8 || !verified {
		t.Fatalf("the accepted timeline was not recorded: %d %v", tl, verified)
	}
}

// TestHR496_NothingServesAfterAnUnacceptedPromotion: once the running
// process sees a promotion it cannot accept, no connection serves a
// decision: not the idle one opened before, not one in use at the time
// (destroyed on release), not a new one (G0 M19 D213, D218).
// Covers: PN-010.7
func TestHR496_NothingServesAfterAnUnacceptedPromotion(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	app := d.AppPool(t)
	org := createOrg(t, app, "after-the-promotion")
	if _, err := app.CheckPromotion(ctx, db.ReplicationAsync); err != nil {
		t.Fatal(err)
	}
	read := func() error {
		return app.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			var n int
			return tx.QueryRow(ctx, "SELECT count(*) FROM pc.orgs").Scan(&n)
		})
	}
	if err := read(); err != nil { // leaves an idle pooled connection
		t.Fatal(err)
	}
	held, err := app.Pgx().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(db.BreakTimelineForTest(app), db.ErrTimelineChanged) || !app.TimelineChanged() {
		t.Fatal("the watch did not break")
	}
	if err := read(); !errors.Is(err, db.ErrTimelineChanged) {
		t.Fatalf("a transaction after the break: %v", err)
	}
	if c, err := app.Pgx().Acquire(ctx); !errors.Is(err, db.ErrTimelineChanged) {
		if c != nil {
			c.Release()
		}
		t.Fatalf("a pooled connection after the break: %v", err)
	}
	held.Release() // pgxpool finishes a release in the background
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		st := app.Pgx().Stat()
		if st.IdleConns() == 0 && st.AcquiredConns() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connections left after the break: %d idle, %d acquired", st.IdleConns(), st.AcquiredConns())
		}
	}
	if err := read(); !errors.Is(err, db.ErrTimelineChanged) {
		t.Fatalf("a transaction after the release: %v", err)
	}
}
