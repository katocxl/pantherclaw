// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// TestHR693_TokenAccountsRefuseOverTheCap: a token account reserves like a
// money one, and a reservation past its cap is refused naming tokens used
// of the cap; a run's account is locked after every grant's (G0 M29 D821,
// D822).
//
// Covers: F982, F983, HR-693, HR-048
func TestHR693_TokenAccountsRefuseOverTheCap(t *testing.T) {
	limit := money.MustParse("1000")
	tok := &Account{ID: ids.NewV7(), Rank: 1, Unit: UnitTokens, Limit: &limit}
	run := &Account{ID: ids.NewV7(), Rank: RunRank, Unit: UnitTokens, Limit: &limit}
	b := &Book{Accounts: map[ids.UUID]*Account{tok.ID: tok, run.ID: run}, Counters: map[ids.UUID]*Counter{}}
	lines := []Line{
		{Kind: KindBudget, ID: run.ID, Rank: run.Rank, Amount: money.MustParse("600")},
		{Kind: KindBudget, ID: tok.ID, Rank: tok.Rank, Amount: money.MustParse("600")},
	}
	if o := Order(lines); o[0].ID != tok.ID || o[1].ID != run.ID {
		t.Fatal("the run's token account is not locked last")
	}
	if _, err := b.Reserve(lines); err != nil {
		t.Fatal(err)
	}
	failed, err := b.Reserve(lines)
	if !errors.Is(err, ErrExhausted) || failed.ID != tok.ID || !strings.Contains(err.Error(), "600 of 1000 tokens used") {
		t.Fatalf("over the cap: %v (line %v)", err, failed.ID)
	}
	if !tok.Reserved.Equal(money.MustParse("600")) || !run.Reserved.Equal(money.MustParse("600")) {
		t.Fatal("a refused reservation changed the book")
	}
	for _, g := range []Unit{UnitCurrency, UnitTokens} {
		if !g.Valid() {
			t.Fatalf("%s invalid", g)
		}
	}
	if Unit("").OrCurrency() != UnitCurrency || Unit("kg").Valid() {
		t.Fatal("units")
	}
}
