// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds budgets and counters (HR-048, HR-049, F110–F119):
// the accounts an action debits, the fixed order in which they are locked,
// and all-or-nothing reservation, commit and release. Grants and envelopes
// declare the rules (internal/grants/domain); this package keeps the
// arithmetic and the ordering pure, so the database adapter only has to
// apply it with conditional updates.
package domain

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Errors.
var (
	// ErrExhausted reports that a reservation would exceed a limit.
	ErrExhausted = errors.New("budgets: limit reached")
	// ErrInvalid reports a malformed rule or a reservation that does not
	// fit its account (another currency, a negative amount).
	ErrInvalid = errors.New("budgets: invalid")
)

// Grouping says what a budget is shared by (F059, F116).
type Grouping string

// Groupings. A task budget belongs to one grant and is shared by its runs
// and, through ancestor debiting, by every grant delegated from it.
const (
	GroupTask      Grouping = "task"
	GroupPrincipal Grouping = "principal"
	GroupAccount   Grouping = "account"
	GroupTeam      Grouping = "team"
	GroupOrg       Grouping = "org"
)

// Valid reports whether g is a known grouping.
func (g Grouping) Valid() bool {
	return slices.Contains([]Grouping{GroupTask, GroupPrincipal, GroupAccount, GroupTeam, GroupOrg}, g)
}

// Period is the window a budget resets on, in UTC.
type Period string

// Periods.
const (
	PeriodNone  Period = "none"
	PeriodDay   Period = "day"
	PeriodWeek  Period = "week"
	PeriodMonth Period = "month"
)

// Valid reports whether p is a known period.
func (p Period) Valid() bool {
	return slices.Contains([]Period{PeriodNone, PeriodDay, PeriodWeek, PeriodMonth}, p)
}

// epoch is the start of the single window of PeriodNone and WindowNone.
var epoch = time.Unix(0, 0).UTC()

// Start returns the start of the period containing t (weeks start on
// Monday). A reservation and its later commit or release always use the
// period of the reservation (ARCHITECTURE §6.3).
func (p Period) Start(t time.Time) time.Time {
	t = t.UTC()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	switch p {
	case PeriodDay:
		return day
	case PeriodWeek:
		return day.AddDate(0, 0, -((int(day.Weekday()) + 6) % 7))
	case PeriodMonth:
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	case PeriodNone:
	}
	return epoch
}

// Window is the window a counter counts in, in UTC.
type Window string

// Windows.
const (
	WindowNone   Window = "none"
	WindowMinute Window = "minute"
	WindowHour   Window = "hour"
	WindowDay    Window = "day"
)

// Valid reports whether w is a known window.
func (w Window) Valid() bool {
	return slices.Contains([]Window{WindowNone, WindowMinute, WindowHour, WindowDay}, w)
}

// Start returns the start of the window containing t.
func (w Window) Start(t time.Time) time.Time {
	t = t.UTC()
	switch w {
	case WindowMinute:
		return t.Truncate(time.Minute)
	case WindowHour:
		return t.Truncate(time.Hour)
	case WindowDay:
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	case WindowNone:
	}
	return epoch
}

// MaxCounterRows caps the counter rows of one rule in one window of one org
// (T-023); past it a decision is CANNOT_AUTHORIZE.
const MaxCounterRows = 10_000

// Owner is the grant or envelope that declares a rule. Rank orders locks:
// envelopes first (0), then grants from the root down (depth + 1). It is
// what makes the lock order "ancestor first" (HR-048). A run with a token
// cap owns one more account, locked last (G0 M29 D822).
type Owner struct {
	Kind string // "grant", "envelope" or "run"
	ID   ids.UUID
	Rank int
}

// Owner kinds.
const (
	OwnerGrant    = "grant"
	OwnerEnvelope = "envelope"
	// OwnerRun owns a run's token cap (G0 M29 D822).
	OwnerRun = "run"
)

// RunRank is the rank of a run's token account: one past the deepest
// grant's (grants rank depth + 1, depth at most 4), so it is locked last
// (G0 M29 D822, HR-048).
const RunRank = 6

// RunTokensRule is the rule id of a run's token cap (G0 M29 D822).
const RunTokensRule = "run_tokens"

// Unit is what a budget account counts (G0 M29 D821).
type Unit string

// Units. The zero value counts as UnitCurrency: every account before M29.
const (
	UnitCurrency Unit = "currency"
	UnitTokens   Unit = "tokens"
)

// Valid reports whether u is a known unit.
func (u Unit) Valid() bool { return u == UnitCurrency || u == UnitTokens }

// OrCurrency is u, or UnitCurrency when unset.
func (u Unit) OrCurrency() Unit {
	if u == "" {
		return UnitCurrency
	}
	return u
}

// Ref names one account or counter row before it is resolved to a row id:
// the declaring owner, the rule, the grouping key and the window start.
type Ref struct {
	Owner Owner
	Rule  string
	Key   [sha256.Size]byte
	Start time.Time
}

// KeyHash hashes a grouping or counter key value. Only the hash is stored,
// so counters keyed by a customer or an account hold no identifiers.
func KeyHash(owner Owner, rule, value string) [sha256.Size]byte {
	return sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%s\x00%s", owner.Kind, owner.ID, rule, value))
}

// Debit is what one action reserves against one budget account.
type Debit struct {
	Ref      Ref
	Grouping Grouping
	Period   Period
	// Unit is what the amount counts: money (Currency set or count-only) or
	// model tokens (no Currency; Limit is the token cap; G0 M29 D821).
	Unit Unit
	// Currency and Limit bound the amount; MaxCount bounds the number of
	// actions. A rule sets either or both.
	Currency money.Currency
	Limit    *money.Decimal
	MaxCount *int64
	// Amount is the value reserved (zero for a count-only budget).
	Amount money.Decimal
}

// CounterDebit is what one action counts against one counter row.
type CounterDebit struct {
	Ref    Ref
	Window Window
	Max    int64
	// MaxOutstanding, when set, bounds the actions reserved but not yet
	// settled (a concurrency limit, F112).
	MaxOutstanding *int64
}
