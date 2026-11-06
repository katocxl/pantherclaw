// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// TestT313_SplitOrUnknownCallsCannotRunPastATokenCap: an agent splitting
// its spend into small calls gets as many as the cap holds and no more,
// and a call whose outcome is UNKNOWN keeps its reservation, so retrying
// around it does not free the cap; only a released (failed) call does
// (G0 M29 D821, HR-003).
//
// Covers: HR-693
func TestT313_SplitOrUnknownCallsCannotRunPastATokenCap(t *testing.T) {
	limit := money.MustParse("1000")
	a := &Account{ID: ids.NewV7(), Rank: 1, Unit: UnitTokens, Limit: &limit}
	b := &Book{Accounts: map[ids.UUID]*Account{a.ID: a}, Counters: map[ids.UUID]*Counter{}}
	call := []Line{{Kind: KindBudget, ID: a.ID, Rank: a.Rank, Amount: money.MustParse("150")}}
	n := 0
	for range 10 {
		if _, err := b.Reserve(call); err != nil {
			if !errors.Is(err, ErrExhausted) {
				t.Fatal(err)
			}
			break
		}
		n++
	}
	if n != 6 {
		t.Fatalf("%d calls of 150 fit a cap of 1000", n)
	}
	b.Settle(call, Hold) // UNKNOWN
	if _, err := b.Reserve(call); !errors.Is(err, ErrExhausted) {
		t.Fatalf("an unknown call freed its reservation: %v", err)
	}
	b.Settle(call, Release) // FAILED
	if _, err := b.Reserve(call); err != nil {
		t.Fatalf("a released call's tokens: %v", err)
	}
	if !a.Reserved.Equal(money.MustParse("900")) {
		t.Fatalf("reserved %s", a.Reserved)
	}
}
