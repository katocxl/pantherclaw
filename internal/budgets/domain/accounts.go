// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Account is the state of one budget row: a limit on value, on the number
// of actions, or both, and what is reserved and spent against it.
type Account struct {
	ID   ids.UUID
	Rank int
	// Unit is what Limit, Reserved and Spent count (G0 M29 D821); unset is
	// UnitCurrency.
	Unit          Unit
	Currency      money.Currency
	Limit         *money.Decimal
	Reserved      money.Decimal
	Spent         money.Decimal
	MaxCount      *int64
	ReservedCount int64
	SpentCount    int64
}

// Available returns what can still be reserved (F113): the amount (nil
// when there is no amount limit) and the count (nil when there is no count
// limit). Unresolved (UNKNOWN) reservations stay reserved, so they reduce
// it (F115).
func (a Account) Available() (*money.Decimal, *int64) {
	var amt *money.Decimal
	if a.Limit != nil {
		used, err := a.Spent.Add(a.Reserved)
		if err == nil {
			left, err := a.Limit.Sub(used)
			if err == nil {
				amt = &left
			}
		}
	}
	var cnt *int64
	if a.MaxCount != nil {
		left := *a.MaxCount - a.SpentCount - a.ReservedCount
		cnt = &left
	}
	return amt, cnt
}

// fits reports whether amount and one more action fit the account.
func (a Account) fits(amount money.Decimal) error {
	if amount.Sign() < 0 {
		return fmt.Errorf("%w: negative amount", ErrInvalid)
	}
	if a.Limit != nil {
		used, err := a.Spent.Add(a.Reserved)
		if err != nil {
			return err
		}
		if used, err = used.Add(amount); err != nil {
			return err
		}
		if used.Cmp(*a.Limit) > 0 {
			if a.Unit == UnitTokens {
				// G0 M29 D821: "N of M tokens used".
				held, _ := a.Spent.Add(a.Reserved)
				return fmt.Errorf("%w: %s of %s tokens used", ErrExhausted, held, *a.Limit)
			}
			return fmt.Errorf("%w: %s %s left", ErrExhausted, mustSub(*a.Limit, a.Spent, a.Reserved), a.Currency)
		}
	}
	if a.MaxCount != nil && a.SpentCount+a.ReservedCount+1 > *a.MaxCount {
		return fmt.Errorf("%w: %d of %d actions used", ErrExhausted, a.SpentCount+a.ReservedCount, *a.MaxCount)
	}
	return nil
}

func mustSub(limit, spent, reserved money.Decimal) money.Decimal {
	used, _ := spent.Add(reserved)
	left, _ := limit.Sub(used)
	return left
}

// Counter is the state of one counter row (HR-049).
type Counter struct {
	ID             ids.UUID
	Rank           int
	Max            int64
	MaxOutstanding *int64
	Reserved       int64
	Spent          int64
}

func (c Counter) fits() error {
	if c.Reserved+c.Spent+1 > c.Max {
		return fmt.Errorf("%w: %d of %d used in this window", ErrExhausted, c.Reserved+c.Spent, c.Max)
	}
	if c.MaxOutstanding != nil && c.Reserved+1 > *c.MaxOutstanding {
		return fmt.Errorf("%w: %d actions already outstanding", ErrExhausted, c.Reserved)
	}
	return nil
}

// Kind of a row in a reservation.
type Kind int

// Row kinds.
const (
	KindBudget Kind = iota
	KindCounter
)

// Line is one row a reservation updates: a budget account with an amount,
// or a counter. Every line counts one action.
type Line struct {
	Kind   Kind
	ID     ids.UUID
	Rank   int
	Amount money.Decimal
}

// Order sorts lines into the one lock order every transaction uses (HR-048):
// by rank, so guardrail accounts come before grant accounts and an
// ancestor's before its descendants', then by id. Two transactions that
// both follow it cannot deadlock on these rows.
func Order(lines []Line) []Line {
	out := slices.Clone(lines)
	slices.SortStableFunc(out, func(a, b Line) int {
		if a.Rank != b.Rank {
			return a.Rank - b.Rank
		}
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	return out
}

// Outcome of a dispatched action, for settlement.
type Outcome int

// Settlement outcomes: an accepted action commits its reservation, a failed
// or expired one releases it, and an UNKNOWN one keeps it (HR-003, F115).
const (
	Commit Outcome = iota
	Release
	Hold
)

// Book is the pure model of a set of accounts and counters. The database
// adapter applies the same rules with conditional updates; the model is
// what the property tests check them against.
type Book struct {
	Accounts map[ids.UUID]*Account
	Counters map[ids.UUID]*Counter
}

// NewBook returns an empty book.
func NewBook() *Book {
	return &Book{Accounts: map[ids.UUID]*Account{}, Counters: map[ids.UUID]*Counter{}}
}

// Reserve reserves every line or none of them: the first line that does not
// fit leaves the book unchanged and returns ErrExhausted with that line.
func (b *Book) Reserve(lines []Line) (Line, error) {
	for _, l := range Order(lines) {
		switch l.Kind {
		case KindBudget:
			a, ok := b.Accounts[l.ID]
			if !ok {
				return l, fmt.Errorf("%w: unknown account", ErrInvalid)
			}
			if err := a.fits(l.Amount); err != nil {
				return l, err
			}
		case KindCounter:
			c, ok := b.Counters[l.ID]
			if !ok {
				return l, fmt.Errorf("%w: unknown counter", ErrInvalid)
			}
			if err := c.fits(); err != nil {
				return l, err
			}
		}
	}
	for _, l := range lines {
		switch l.Kind {
		case KindBudget:
			a := b.Accounts[l.ID]
			a.Reserved, _ = a.Reserved.Add(l.Amount)
			a.ReservedCount++
		case KindCounter:
			b.Counters[l.ID].Reserved++
		}
	}
	return Line{}, nil
}

// Settle applies an outcome to every line of an earlier reservation.
func (b *Book) Settle(lines []Line, o Outcome) {
	if o == Hold {
		return
	}
	for _, l := range lines {
		switch l.Kind {
		case KindBudget:
			a := b.Accounts[l.ID]
			a.Reserved, _ = a.Reserved.Sub(l.Amount)
			a.ReservedCount--
			if o == Commit {
				a.Spent, _ = a.Spent.Add(l.Amount)
				a.SpentCount++
			}
		case KindCounter:
			c := b.Counters[l.ID]
			c.Reserved--
			if o == Commit {
				c.Spent++
			}
		}
	}
}

// Check reports whether lines would fit now, without reserving (the
// read-only check of pipeline step 7). The binding check is the
// reservation in the finalization transaction.
func (b *Book) Check(lines []Line) (Line, error) {
	clone := &Book{Accounts: map[ids.UUID]*Account{}, Counters: map[ids.UUID]*Counter{}}
	for id, a := range b.Accounts {
		c := *a
		clone.Accounts[id] = &c
	}
	for id, c := range b.Counters {
		cc := *c
		clone.Counters[id] = &cc
	}
	return clone.Reserve(lines)
}
