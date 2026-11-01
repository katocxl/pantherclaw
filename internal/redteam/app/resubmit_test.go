// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

func TestResubmitSendsAgainOnlyWhileTheCallIsBusy(t *testing.T) {
	busy := domain.Observation{Outcome: domain.OutcomeCannotAuthorize, Reason: domain.RetryBudgetBusy}
	final := domain.Observation{Outcome: domain.OutcomeDeny, Reason: "BUDGET_EXHAUSTED"}
	calls := 0
	got, err := Resubmit(context.Background(), domain.RetryBudgetBusy, func(attempt int) (domain.Observation, error) {
		if attempt != calls {
			t.Errorf("attempt %d on call %d", attempt, calls)
		}
		calls++
		if calls < 3 {
			return busy, nil
		}
		return final, nil
	})
	if err != nil || calls != 3 || got.Outcome != domain.OutcomeDeny {
		t.Fatalf("%d calls: %+v, %v", calls, got, err)
	}
}

// TestResubmitIsBoundedAndKeepsTheLastAnswer: a call that stays busy ends
// busy, so the step's expectation fails it. Nothing turns it into a pass.
func TestResubmitIsBoundedAndKeepsTheLastAnswer(t *testing.T) {
	busy := domain.Observation{Outcome: domain.OutcomeCannotAuthorize, Reasons: []string{domain.RetryBudgetBusy}}
	calls := 0
	got, err := Resubmit(context.Background(), domain.RetryBudgetBusy, func(int) (domain.Observation, error) {
		calls++
		return busy, nil
	})
	if err != nil || calls != resubmits+1 || got.Outcome != domain.OutcomeCannotAuthorize {
		t.Fatalf("%d calls: %+v, %v", calls, got, err)
	}
}

func TestResubmitWithoutRetryOnSendsOnce(t *testing.T) {
	calls := 0
	_, err := Resubmit(context.Background(), "", func(int) (domain.Observation, error) {
		calls++
		return domain.Observation{Code: domain.RetryBudgetBusy}, nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("%d calls, %v", calls, err)
	}
}

func TestResubmitStopsOnAnError(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	_, err := Resubmit(context.Background(), domain.RetryBudgetBusy, func(int) (domain.Observation, error) {
		calls++
		return domain.Observation{}, boom
	})
	if !errors.Is(err, boom) || calls != 1 {
		t.Fatalf("%d calls, %v", calls, err)
	}
}
