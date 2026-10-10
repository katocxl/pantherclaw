// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app

import (
	"context"
	"testing"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

// TestT042_TheObserverRecordsTheWindowsClosedEntries: each org's entries
// closed in the job's window are recorded once; entries closed before it
// are not.
func TestT042_TheObserverRecordsTheWindowsClosedEntries(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org, user := ids.New[ids.Org](), ids.NewV7()
	var inWindow, before ids.UUID
	if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org); err != nil {
			return err
		}
		var err error
		if inWindow, err = pgwaitlist.OpenToolReview(ctx, tx, org, ids.NewV7(), "pc.mock-payments", "1.0.0", pgwaitlist.System); err != nil {
			return err
		}
		before, err = pgwaitlist.OpenToolReview(ctx, tx, org, ids.NewV7(), "pc.mock-payments", "1.0.1", pgwaitlist.System)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	d.AdminExec(t, `UPDATE pc.waitlist_entries SET created_at = now() - interval '10 minutes', state = 'APPROVED', decided_by = $2,
		decided_at = now() - interval '9 minutes' WHERE id = $1`, inWindow, "user:"+user.String())
	d.AdminExec(t, `UPDATE pc.waitlist_entries SET created_at = now() - interval '2 hours', state = 'APPROVED', decided_by = $2,
		decided_at = now() - interval '1 hour' WHERE id = $1`, before, "user:"+user.String())
	var got []recorded
	h, err := NewHistograms(fakeMeter{got: &got})
	if err != nil {
		t.Fatal(err)
	}
	w := &observeWorker{pool: p, h: h}
	until := time.Now().Add(-6 * time.Minute)
	if err := w.Work(context.Background(), &river.Job[ObserveArgs]{Args: ObserveArgs{Until: until}}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].value != 60 || got[1].value != 60 {
		t.Fatalf("recorded %v", got)
	}
}
