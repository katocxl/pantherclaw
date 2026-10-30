// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"context"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// busyStore answers ErrBusy to the first busy finalizations that reserve
// (a permit), as a hot budget row past its lock timeout does, and records
// every evaluation a finalization was asked to bind. onBusy runs after each
// busy answer.
type busyStore struct {
	finalize.Store
	busy   int
	onBusy func()
	bound  []*pipeline.Evaluation
}

func (s *busyStore) Finalize(ctx context.Context, org ids.OrgID, w finalize.Write) error {
	s.bound = append(s.bound, w.Eval)
	if w.Permit != nil && s.busy > 0 {
		s.busy--
		if s.onBusy != nil {
			s.onBusy()
		}
		return finalize.ErrBusy
	}
	return s.Store.Finalize(ctx, org, w)
}

func busyScenario(t *testing.T, busy int) (*pipelinetest.Scenario, *busyStore, *snapshotWorld, ids.UUID) {
	t.Helper()
	s, _, run := scenario(t)
	snap := &snapshotWorld{World: s.W}
	s.Authority.Pipeline = &pipeline.Pipeline{Reader: snap}
	store := &busyStore{Store: s.W, busy: busy}
	s.Authority.Store = store
	return s, store, snap, run
}

// TestHR505_ABusyBudgetIsRetriedOnceFromAFreshSnapshot: one busy answer is
// retried once, after a jittered wait, from a new snapshot and a new
// evaluation, and the action is allowed.
// Covers: PN-011.1
func TestHR505_ABusyBudgetIsRetriedOnceFromAFreshSnapshot(t *testing.T) {
	s, store, snap, run := busyScenario(t, 1)
	start := time.Now()
	res := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	took := time.Since(start)
	if res.Decision != adomain.Allow || res.Permit == "" {
		t.Fatalf("after one busy answer: %s %s", res.Decision, decisive(res))
	}
	if snap.taken != 2 || len(store.bound) != 2 {
		t.Fatalf("%d snapshots and %d finalizations; want 2 and 2", snap.taken, len(store.bound))
	}
	if store.bound[0] == store.bound[1] {
		t.Fatal("the retry bound the busy evaluation again")
	}
	if took < 5*time.Millisecond {
		t.Fatalf("the retry did not wait its jitter: %v", took)
	}
}

// TestHR505_BusyTwiceIsBudgetBusy: a row still busy at the retry gives
// CANNOT_AUTHORIZE BUDGET_BUSY with no permit, after exactly one retry.
// Covers: PN-011.1
func TestHR505_BusyTwiceIsBudgetBusy(t *testing.T) {
	s, store, snap, run := busyScenario(t, 100)
	res := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	if res.Decision != adomain.CannotAuthorize || decisive(res) != finalize.ReasonBudgetBusy || res.Permit != "" {
		t.Fatalf("a busy budget: %s %s permit %q", res.Decision, decisive(res), res.Permit)
	}
	if busy := 100 - store.busy; busy != 2 || snap.taken != 2 {
		t.Fatalf("%d busy finalizations over %d snapshots; want one retry (2 and 2)", busy, snap.taken)
	}
	// The BUDGET_BUSY answer is recorded without reservations, from the
	// retry's own evaluation.
	if n := len(store.bound); n != 3 || store.bound[2].Plan.Budgets != nil {
		t.Fatalf("%d finalizations, last plan %+v", n, store.bound[n-1].Plan)
	}
}

// TestT219_ARetriedDecisionNeverUsesAStaleEvaluation: the kill switch is
// engaged while the first finalization waits on a busy row; the retry
// evaluates again, sees it and issues no permit.
// Covers: PN-011.1
func TestT219_ARetriedDecisionNeverUsesAStaleEvaluation(t *testing.T) {
	s, store, _, run := busyScenario(t, 1)
	store.onBusy = func() { s.W.Cont.KillSwitch = true }
	res := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	if res.Permit != "" || res.Decision.Permits() {
		t.Fatalf("the retry bound a stale evaluation: %s %s", res.Decision, decisive(res))
	}
	if store.bound[0].Decision != adomain.Allow {
		t.Fatalf("the first evaluation was %s; the test needs an ALLOW", store.bound[0].Decision)
	}
}
