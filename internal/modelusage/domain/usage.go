// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds model usage (G0 M29 D825; F987, F988; HR-698): the
// token counts one model call reported, the cost estimate from the prices an
// organization set on its model connection, the UTC month a report covers
// and the rows of the monthly token report. It is pure: the database adapter
// stores and sums the rows, this package does the arithmetic.
package domain

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Statement is the fixed statement every token report carries (D825).
const Statement = "Token counts are what the model providers reported. " +
	"Costs are estimates from prices your organization set, not a bill."

// EstimateLabel marks an estimate wherever it appears (HR-698).
const EstimateLabel = "estimate"

// MaxTokens is the largest count of one kind one call may report (D818).
const MaxTokens = 1_000_000_000

// MaxModelLength is the longest model id a row keeps.
const MaxModelLength = 256

// ErrInvalid reports a usage, price, month or row that is out of range.
var ErrInvalid = errors.New("modelusage: invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// Usage is what one model call used, normalised across providers (D818):
// OpenAI's cached prompt tokens are cache reads, not input tokens.
// Reported is false when the answer carried no usage; the counts are then 0.
type Usage struct {
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	Reported         bool
}

// Validate checks each count is 0..MaxTokens and an unreported usage has
// none.
func (u Usage) Validate() error {
	for _, n := range []int64{u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens} {
		if n < 0 || n > MaxTokens {
			return invalid("token counts are 0..%d", MaxTokens)
		}
	}
	if !u.Reported && u.Total() != 0 {
		return invalid("unreported usage carries no counts")
	}
	return nil
}

// Total is the four counts summed (D818). A valid usage cannot overflow.
func (u Usage) Total() int64 {
	return u.InputTokens + u.OutputTokens + u.CacheReadTokens + u.CacheWriteTokens
}

// Price is a model connection's optional price per million tokens (D811).
// A nil cache price is the input price.
type Price struct {
	Currency   money.Currency
	Input      money.Decimal
	Output     money.Decimal
	CacheRead  *money.Decimal
	CacheWrite *money.Decimal
}

// Validate checks the currency and that every price is non-negative.
func (p Price) Validate() error {
	if _, err := money.ParseCurrency(string(p.Currency)); err != nil {
		return invalid("price currency %q", p.Currency)
	}
	for _, d := range []*money.Decimal{&p.Input, &p.Output, p.CacheRead, p.CacheWrite} {
		if d != nil && d.Sign() < 0 {
			return invalid("prices are not negative")
		}
	}
	return nil
}

// million is the price unit: prices are per million tokens.
var million = big.NewInt(1_000_000)

// Estimate is the cost estimate of one call (D825): (input × in +
// cache_read × (cache read price, else in) + cache_write × (cache write
// price, else in) + output × out) / 1,000,000, rounded half up to 8
// fraction digits, in the price's currency. It is an estimate, never a
// bill (HR-698).
func Estimate(u Usage, p Price) (Amount, error) {
	if err := u.Validate(); err != nil {
		return Amount{}, err
	}
	if err := p.Validate(); err != nil {
		return Amount{}, err
	}
	cacheRead, cacheWrite := p.Input, p.Input
	if p.CacheRead != nil {
		cacheRead = *p.CacheRead
	}
	if p.CacheWrite != nil {
		cacheWrite = *p.CacheWrite
	}
	// Units are 10^-8; the sum is in 10^-8 per million.
	sum := new(big.Int)
	for _, t := range []struct {
		n     int64
		price money.Decimal
	}{{u.InputTokens, p.Input}, {u.CacheReadTokens, cacheRead}, {u.CacheWriteTokens, cacheWrite}, {u.OutputTokens, p.Output}} {
		pu, err := units(t.price)
		if err != nil {
			return Amount{}, err
		}
		sum.Add(sum, pu.Mul(pu, big.NewInt(t.n)))
	}
	amount, err := fromUnits(divHalfUp(sum, million))
	if err != nil {
		return Amount{}, err
	}
	return Amount{Currency: p.Currency, Amount: amount}, nil
}

// Amount is an estimate in one currency. It keeps 8 fraction digits
// whatever the currency's minor unit: an estimate is not a payable amount.
type Amount struct {
	Currency money.Currency
	Amount   money.Decimal
}

// divHalfUp divides a non-negative n by d, rounding half up.
func divHalfUp(n, d *big.Int) *big.Int {
	q, r := new(big.Int).QuoRem(n, d, new(big.Int))
	if new(big.Int).Lsh(r, 1).Cmp(d) >= 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

// units returns d × 10^8 as an integer.
func units(d money.Decimal) (*big.Int, error) {
	s, err := d.StringFixed(money.MaxScale)
	if err != nil {
		return nil, err
	}
	u, ok := new(big.Int).SetString(strings.Replace(s, ".", "", 1), 10)
	if !ok {
		return nil, invalid("decimal %q", s)
	}
	return u, nil
}

// fromUnits is the decimal of u × 10^-8 (u ≥ 0), or money.ErrOverflow.
func fromUnits(u *big.Int) (money.Decimal, error) {
	s := u.String()
	if pad := money.MaxScale + 1 - len(s); pad > 0 {
		s = strings.Repeat("0", pad) + s
	}
	d, err := money.Parse(s[:len(s)-money.MaxScale] + "." + s[len(s)-money.MaxScale:])
	if err != nil {
		return money.Decimal{}, money.ErrOverflow
	}
	return d, nil
}

// Month is one UTC calendar month: [Start, End).
type Month struct {
	Start time.Time
	End   time.Time
}

// ParseMonth parses YYYY-MM (D825) as a UTC month.
func ParseMonth(s string) (Month, error) {
	t, err := time.Parse("2006-01", s)
	if err != nil || t.Format("2006-01") != s {
		return Month{}, invalid("month %q is not YYYY-MM", s)
	}
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	return Month{Start: start, End: start.AddDate(0, 1, 0)}, nil
}

// String is the month as YYYY-MM.
func (m Month) String() string { return m.Start.Format("2006-01") }

// Outcome is a model call's recorded outcome (D825).
type Outcome string

// Outcomes a usage row may carry.
const (
	OutcomeAccepted  Outcome = "ACCEPTED"
	OutcomeDelegated Outcome = "DELEGATED"
	OutcomeFailed    Outcome = "FAILED"
	OutcomeUnknown   Outcome = "UNKNOWN"
)

// Valid reports whether o is one of the outcomes.
func (o Outcome) Valid() bool {
	return slices.Contains([]Outcome{OutcomeAccepted, OutcomeDelegated, OutcomeFailed, OutcomeUnknown}, o)
}

// GroupBy is what a report's rows sum by (D825).
type GroupBy string

// Groupings.
const (
	ByTeam       GroupBy = "team"
	ByAgent      GroupBy = "agent"
	ByConnection GroupBy = "connection"
	ByModel      GroupBy = "model"
)

// Valid reports whether g is one of the groupings.
func (g GroupBy) Valid() bool {
	return slices.Contains([]GroupBy{ByTeam, ByAgent, ByConnection, ByModel}, g)
}
