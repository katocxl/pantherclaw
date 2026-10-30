// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
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

// busyCounting counts the finalizations that found a budget row busy.
type busyCounting struct {
	finalize.Store
	busy atomic.Int32
}

func (s *busyCounting) Finalize(ctx context.Context, org ids.OrgID, w finalize.Write) error {
	err := s.Store.Finalize(ctx, org, w)
	if errors.Is(err, finalize.ErrBusy) {
		s.busy.Add(1)
	}
	return err
}

// waitBudgetLock returns once a statement on pc.budget_accounts is waiting
// for a lock, the moment its lock timeout starts.
func (w *world) waitBudgetLock() error {
	w.t.Helper()
	var err error
	w.db.AdminDo(w.t, func(conn *pgx.Conn) error {
		ctx := context.Background()
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
			var waiting int
			if err = conn.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
				AND wait_event_type = 'Lock' AND query LIKE '%budget_accounts%'`).Scan(&waiting); err != nil || waiting > 0 {
				return nil
			}
			time.Sleep(2 * time.Millisecond)
		}
		err = errors.New("no statement waited for a budget row")
		return nil
	})
	return err
}

// TestT219_RacingFirstOfPeriodRefundsNeverOverspend: a refund whose budget
// row is still held 110 ms after it started waiting, past the 100 ms lock
// timeout, is busy exactly once and allowed by its one retry, reserving
// once. Then refunds racing on budgets
// none of them has reserved on yet (each first of its period, so each
// prepares the row) never reserve past the limit, and every budget gets
// exactly one row.
// Covers: PN-011.1
func TestT219_RacingFirstOfPeriodRefundsNeverOverspend(t *testing.T) {
	w := newWorld(t)
	w.auth.Store.(*pgauthority.Store).LockTimeout = 100 * time.Millisecond
	ctx := context.Background()

	w.refundable("ch_held1", "ch_held2")
	held := w.run(w.grant("50").ID, ids.UUID{})
	if r := w.authorize(w.request(held, ids.NewV7(), "ch_held1", "5.00")); r.Permit == "" {
		t.Fatalf("the first refund prepares the row: %s %s", r.Decision, decisive(r))
	}
	counted := &busyCounting{Store: w.auth.Store}
	w.auth.Store = counted
	release := w.holdBudgetRows()
	type answer struct {
		res  finalize.Result
		err  error
		took time.Duration
	}
	done := make(chan answer, 1)
	go func() {
		start := time.Now()
		res, err := w.auth.Authorize(ctx, w.gw, w.request(held, ids.NewV7(), "ch_held2", "5.00"))
		done <- answer{res, err, time.Since(start)}
	}()
	waited := w.waitBudgetLock()
	time.Sleep(110 * time.Millisecond)
	release()
	a := <-done
	w.auth.Store = counted.Store
	if waited != nil {
		t.Fatal(waited)
	}
	if a.err != nil || a.res.Decision != adomain.Allow || a.res.Permit == "" {
		t.Fatalf("held 110 ms past the wait: %s %s %v; want an ALLOW from the one retry", a.res.Decision, decisive(a.res), a.err)
	}
	if n := counted.busy.Load(); n != 1 {
		t.Fatalf("%d finalizations found the row busy; want exactly 1", n)
	}
	if a.took < 100*time.Millisecond {
		t.Fatalf("allowed after %v, before the first attempt's lock timeout: no busy retry happened", a.took)
	}
	if res, _ := w.budget(); res != "10" {
		t.Fatalf("after the busy retry %s is reserved; want 10 (two refunds of 5.00, each once)", res)
	}

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
	if rows != budgets+1 || over != 0 { // the held budget and the racing ones
		t.Fatalf("%d budget rows (want %d), %d over their limit", rows, budgets+1, over)
	}
}
