// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR504_DecisionSnapshotsStayRepeatableReadReadOnly: the transaction an
// evaluation reads in is REPEATABLE READ and READ ONLY, so no write can move
// into it: Postgres itself refuses one.
// Covers: PN-011.1
func TestHR504_DecisionSnapshotsStayRepeatableReadReadOnly(t *testing.T) {
	w := newWorld(t)
	reader := w.auth.Pipeline.Reader.(*pgauthority.Reader)
	iso, ro, write, err := pgauthority.SnapshotMode(context.Background(), reader, w.org)
	if err != nil {
		t.Fatal(err)
	}
	if iso != "repeatable read" || ro != "on" {
		t.Fatalf("the decision snapshot is %q, read only %q", iso, ro)
	}
	if pe := new(pgconn.PgError); !errors.As(write, &pe) || pe.Code != "25006" {
		t.Fatalf("a write in the snapshot: %v; want read_only_sql_transaction", write)
	}
}

// TestT219_RacingFirstOfPeriodRefundsNeverOverspend: refunds racing on
// budgets none of them has reserved on yet (each first of its period, so
// each prepares the row) never reserve past the limit, through busy rows
// and their one retry, and every budget gets exactly one row.
// Covers: PN-011.1
func TestT219_RacingFirstOfPeriodRefundsNeverOverspend(t *testing.T) {
	w := newWorld(t)
	w.auth.Store.(*pgauthority.Store).LockTimeout = 100 * time.Millisecond
	const budgets, perBudget = 5, 30
	charges := make([]string, budgets*perBudget)
	for i := range charges {
		charges[i] = fmt.Sprintf("ch_%d", i)
	}
	w.refundable(charges...)
	runs := make([]ids.UUID, budgets)
	for i := range runs {
		runs[i] = w.run(w.grant("50").ID, ids.UUID{})
	}

	ctx := context.Background()
	var mu sync.Mutex
	permits := map[ids.UUID]int{}
	answers := map[string]int{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, charge := range charges {
		run := runs[i%budgets]
		req := w.request(run, ids.NewV7(), charge, "5.00")
		wg.Go(func() {
			<-start
			res, err := w.auth.Authorize(ctx, w.gw, req)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				t.Errorf("a refund got no decision: %v", err)
			case res.Permit != "":
				permits[run]++
			case res.Decision == adomain.Allow:
				t.Error("an ALLOW without a permit")
			default:
				answers[string(res.Decision)+"/"+decisive(res)]++
			}
		})
	}
	close(start)
	wg.Wait()
	t.Logf("permits %v, other answers %v", permits, answers)

	for _, run := range runs {
		if n := permits[run]; n > 10 {
			t.Errorf("run %s: %d permits of 5.00 on a 50.00 budget", run, n)
		}
	}
	var rows, over int
	if err := w.pool.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE reserved + spent > 50) FROM pc.budget_accounts`).Scan(&rows, &over)
	}); err != nil {
		t.Fatal(err)
	}
	if rows != budgets || over != 0 {
		t.Fatalf("%d budget rows (want %d), %d over their limit", rows, budgets, over)
	}
}
