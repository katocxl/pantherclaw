// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// holdBudgetRows locks the org's budget account rows in another
// transaction, as a long finalization would, until the returned function
// is called.
func (w *world) holdBudgetRows() func() {
	w.t.Helper()
	locked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			if _, err := tx.Exec(ctx, "UPDATE pc.budget_accounts SET reserved = reserved"); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-done:
		w.t.Fatalf("hold the budget rows: %v", err)
	}
	return func() {
		close(release)
		if err := <-done; err != nil {
			w.t.Fatal(err)
		}
	}
}

// settling reports whether the audited lister finds the org among those
// with settlements to apply.
func (w *world) settling() bool {
	w.t.Helper()
	refs, err := w.pool.CrossOrgList(context.Background(), db.ListerPurpose("budget_settle"), 10000)
	if err != nil {
		w.t.Fatal(err)
	}
	return slices.ContainsFunc(refs, func(r db.OrgRef) bool { return r.Org == w.org })
}

// TestADR0015_OutcomesSettleOffTheHotRow: RecordExecution records an
// outcome without touching the budget row (it completes while another
// transaction holds the row); the row still counts the outcome as reserved
// until the settlement applies it, exactly once, while the budget view, a
// new receipt and the lister already see it.
func TestADR0015_OutcomesSettleOffTheHotRow(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2", "ch_3")
	g := w.grant("500")
	run := w.run(g.ID, ids.UUID{})
	accepted := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00"))
	failed := w.authorize(w.request(run, ids.NewV7(), "ch_2", "20.00"))
	for _, r := range []finalize.Result{accepted, failed} {
		if _, err := w.auth.BeginDispatch(ctx, w.gw, r.PermitID, r.Epoch, finalize.Outbound{}); err != nil {
			t.Fatal(err)
		}
	}

	release := w.holdBudgetRows()
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	for _, e := range []finalize.Execution{
		{Permit: accepted.PermitID, Outcome: finalize.Accepted, DispatchMS: -1},
		{Permit: failed.PermitID, Outcome: finalize.Failed, DispatchMS: -1},
	} {
		if _, err := w.auth.RecordExecution(rctx, w.gw, e); err != nil {
			t.Fatalf("an outcome waited for the budget row: %v", err)
		}
	}
	cancel()
	release()

	if res, sp := w.rows(); res != "50" || sp != "0" {
		t.Fatalf("before the settlement the row counts both as reserved: reserved %s spent %s", res, sp)
	}
	if !w.settling() {
		t.Fatal("the lister does not find the org's pending settlements")
	}
	view, err := (&gpg.Store{Pool: w.pool}).BudgetAccounts(ctx, w.org, []ids.UUID{g.ID.UUID()})
	if err != nil || len(view) != 1 || view[0].Reserved.String() != "0" || view[0].Spent.String() != "30" || view[0].SpentCount != 1 {
		t.Fatalf("the budget view shows the outcomes settled: %+v %v", view, err)
	}
	third := w.authorize(w.request(run, ids.NewV7(), "ch_3", "5.00"))
	var receipt finalize.DecisionReceipt
	if err := json.Unmarshal([]byte(receiptClaims(t, third.Receipt)), &receipt); err != nil {
		t.Fatal(err)
	}
	if b := receipt.Pap.Budgets; len(b) != 1 || b[0].Reserved != "5" || b[0].Spent != "30" || b[0].Available != "465" {
		t.Fatalf("the receipt shows the budget settled: %+v", b)
	}

	if n, err := w.auth.Store.ApplySettlements(ctx, w.org); err != nil || n != 2 {
		t.Fatalf("applied %d, %v; want the 2 outcomes", n, err)
	}
	if res, sp := w.rows(); res != "5" || sp != "30" {
		t.Fatalf("after the settlement: reserved %s spent %s", res, sp)
	}
	if n, err := w.auth.Store.ApplySettlements(ctx, w.org); err != nil || n != 0 {
		t.Fatalf("a second settlement applied %d, %v; want none", n, err)
	}
	if w.settling() {
		t.Fatal("the lister still finds the org")
	}
}

// TestADR0015_ABusyBudgetFailsFast: while another transaction holds the
// task budget's row for longer than the lock timeout, a refund is refused
// at once with CANNOT_AUTHORIZE BUDGET_BUSY, reserves nothing and gets no
// permit; resubmitted once the row is free, it is decided again and
// allowed.
func TestADR0015_ABusyBudgetFailsFast(t *testing.T) {
	w := newWorld(t)
	w.auth.Store.(*pgauthority.Store).LockTimeout = 100 * time.Millisecond
	w.refundable("ch_1", "ch_2")
	run := w.run(w.grant("500").ID, ids.UUID{})
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "10.00")); r.Permit == "" {
		t.Fatalf("first: %s %s", r.Decision, decisive(r))
	}

	req := w.request(run, ids.NewV7(), "ch_2", "20.00")
	release := w.holdBudgetRows()
	start := time.Now()
	busy := w.authorize(req)
	took := time.Since(start)
	release()
	if busy.Decision != adomain.CannotAuthorize || decisive(busy) != finalize.ReasonBudgetBusy || busy.Permit != "" {
		t.Fatalf("a busy budget: %s %s permit %q", busy.Decision, decisive(busy), busy.Permit)
	}
	if took > 1500*time.Millisecond {
		t.Fatalf("the refusal took %v; it must not queue towards the caller's timeout", took)
	}
	if res, _ := w.budget(); res != "10" {
		t.Fatalf("a busy refusal reserved: %s", res)
	}
	again := w.authorize(req)
	if again.Decision != adomain.Allow || again.Permit == "" || again.TransactionID != busy.TransactionID || again.Evaluation != 2 {
		t.Fatalf("resubmitted: %s %s, evaluation %d", again.Decision, decisive(again), again.Evaluation)
	}
}

// TestHR048_NoOverspendWithFailFastLocksAndAsyncSettlement is the M4 exit
// race (TestHR048_NoOverspendUnder1000ConcurrentAuthorizations) with the
// production settings of ADR-0015: a 50 ms budget lock timeout, and every
// permit dispatched and accepted while settlements are applied
// concurrently. Busy refusals may leave budget unused, but nothing is
// overspent, every answer is a decision, and once settled every account
// equals its reservations.
func TestHR048_NoOverspendWithFailFastLocksAndAsyncSettlement(t *testing.T) {
	w := newWorld(t)
	w.auth.Store.(*pgauthority.Store).LockTimeout = 50 * time.Millisecond
	w.auth.PermitTTL = time.Hour
	ctx := context.Background()
	charges := make([]string, 1000)
	for i := range charges {
		charges[i] = fmt.Sprintf("ch_%d", i)
	}
	w.refundable(charges...)
	g := w.grant("500")
	rootRun := w.run(g.ID, ids.UUID{})
	runs := []ids.UUID{rootRun}
	lim, _ := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "child", "grouping": "task", "operations": ["payments.refund.create"], "currency": "USD", "limit": "300", "period": "none"}]}`))
	for range 2 {
		child := w.run(gdomain.GrantID{}, rootRun)
		if _, err := w.grants.Delegate(ctx, gapp.Workload{Org: w.org, InstanceID: w.instance, RunID: rootRun},
			gapp.DelegateRequest{ChildRunID: child, Limits: lim}); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, child)
	}

	stop := make(chan struct{})
	settled := make(chan error, 1)
	go func() {
		for {
			if _, err := w.auth.Store.ApplySettlements(ctx, w.org); err != nil {
				settled <- err
				return
			}
			select {
			case <-stop:
				settled <- nil
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()

	var mu sync.Mutex
	permits := map[int]int{}
	answers := map[string]int{}
	errs := 0
	var wg sync.WaitGroup
	for i := range 1000 {
		r := 1
		switch i % 10 {
		case 7, 8:
			r = 2
		case 9:
			r = 0
		}
		req := w.request(runs[r], ids.NewV7(), charges[i], "1.00")
		wg.Go(func() {
			res, err := w.auth.Authorize(ctx, w.gw, req)
			if err == nil && res.Permit != "" {
				if _, err = w.auth.BeginDispatch(ctx, w.gw, res.PermitID, res.Epoch, finalize.Outbound{}); err == nil {
					_, err = w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: res.PermitID, Outcome: finalize.Accepted, DispatchMS: -1})
				}
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				errs++
				t.Logf("refund: %v", err)
			case res.Permit != "":
				permits[r]++
			case res.Decision.Permits():
				t.Errorf("an ALLOW without a permit")
			default:
				answers[string(res.Decision)+"/"+decisive(res)]++
			}
		})
	}
	wg.Wait()
	close(stop)
	if err := <-settled; err != nil {
		t.Fatalf("concurrent settlement: %v", err)
	}
	w.settle()

	total := permits[0] + permits[1] + permits[2]
	t.Logf("permits %v, other answers %v", permits, answers)
	if errs > 0 {
		t.Fatalf("%d calls failed instead of deciding", errs)
	}
	if total > 500 || permits[1] > 300 || permits[2] > 300 {
		t.Fatalf("permits %v (total %d): over the shared 500 or a child's 300", permits, total)
	}
	for a := range answers {
		if a != "DENY/"+gdomain.ReasonBudgetExhausted && a != "CANNOT_AUTHORIZE/"+finalize.ReasonBudgetBusy &&
			a != "CANNOT_AUTHORIZE/"+finalize.ReasonConcurrentChange {
			t.Errorf("unexpected answer %s", a)
		}
	}
	if bad := w.count(`SELECT count(*) FROM pc.budget_accounts a WHERE a.reserved_count <> 0 OR a.reserved <> 0
		OR a.spent <> (SELECT coalesce(sum(r.amount), 0) FROM pc.reservations r WHERE r.org_id = a.org_id AND r.account_id = a.id AND r.state = 'COMMITTED')
		OR a.spent_count <> (SELECT count(*) FROM pc.reservations r WHERE r.org_id = a.org_id AND r.account_id = a.id AND r.state = 'COMMITTED')`); bad != 0 {
		t.Fatalf("%d accounts disagree with their reservations once settled", bad)
	}
	if spent := w.scalar(`SELECT spent::integer::text FROM pc.budget_accounts WHERE owner_id = $1`, g.ID.UUID()); spent != fmt.Sprint(total) {
		t.Fatalf("the shared budget spent %s for %d permits", spent, total)
	}
}
