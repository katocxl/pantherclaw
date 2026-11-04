// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/modelusage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

func dec(s string) *money.Decimal {
	d := money.MustParse(s)
	return &d
}

// TestEstimate: the estimate is the per-million prices times the counts,
// cache prices falling back to the input price, half up to 8 places (G0
// M29 D825).
//
// Covers: F987, HR-698
func TestEstimate(t *testing.T) {
	base := domain.Price{Currency: "USD", Input: money.MustParse("3"), Output: money.MustParse("15")}
	cases := []struct {
		name  string
		u     domain.Usage
		p     domain.Price
		want  string
		wantC money.Currency
	}{
		{"input and output", domain.Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000, Reported: true}, base, "18", "USD"},
		{"small call", domain.Usage{InputTokens: 1200, OutputTokens: 340, Reported: true}, base, "0.0087", "USD"},
		{"cache prices default to input", domain.Usage{CacheReadTokens: 1_000_000, CacheWriteTokens: 1_000_000, Reported: true}, base, "6", "USD"},
		{
			"own cache prices",
			domain.Usage{CacheReadTokens: 1_000_000, CacheWriteTokens: 2_000_000, Reported: true},
			domain.Price{Currency: "EUR", Input: money.MustParse("3"), Output: money.MustParse("15"), CacheRead: dec("0.3"), CacheWrite: dec("3.75")},
			"7.8", "EUR",
		},
		// 1 token at 0.00000001 per million is 1e-14: rounds to 0.
		{"rounds down below half", domain.Usage{InputTokens: 1, Reported: true}, domain.Price{Currency: "USD", Input: money.MustParse("0.00000001")}, "0", "USD"},
		// 1 token at 0.005 per million: 0.000000005, exactly half a unit: up.
		{"half rounds up", domain.Usage{InputTokens: 1, Reported: true}, domain.Price{Currency: "USD", Input: money.MustParse("0.005")}, "0.00000001", "USD"},
		{"just under half", domain.Usage{InputTokens: 1, Reported: true}, domain.Price{Currency: "USD", Input: money.MustParse("0.00499999")}, "0", "USD"},
		{"unreported is zero", domain.Usage{}, base, "0", "USD"},
		{"free model", domain.Usage{InputTokens: 5, OutputTokens: 5, Reported: true}, domain.Price{Currency: "USD"}, "0", "USD"},
	}
	for _, tc := range cases {
		got, err := domain.Estimate(tc.u, tc.p)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !got.Amount.Equal(money.MustParse(tc.want)) || got.Currency != tc.wantC {
			t.Errorf("%s: %s %s, want %s %s", tc.name, got.Amount, got.Currency, tc.want, tc.wantC)
		}
	}
}

// TestEstimateRefusesBadInput: counts out of range, negative prices or an
// unknown currency give no estimate; a sum past the decimal range is an
// overflow, never a wrapped number.
//
// Covers: F987
func TestEstimateRefusesBadInput(t *testing.T) {
	ok := domain.Price{Currency: "USD", Input: money.MustParse("1"), Output: money.MustParse("1")}
	bad := []struct {
		name string
		u    domain.Usage
		p    domain.Price
	}{
		{"negative count", domain.Usage{InputTokens: -1, Reported: true}, ok},
		{"count too large", domain.Usage{OutputTokens: domain.MaxTokens + 1, Reported: true}, ok},
		{"unreported with counts", domain.Usage{InputTokens: 1}, ok},
		{"unknown currency", domain.Usage{Reported: true}, domain.Price{Currency: "usd"}},
		{"negative price", domain.Usage{Reported: true}, domain.Price{Currency: "USD", Output: money.MustParse("-1")}},
		{"negative cache price", domain.Usage{Reported: true}, domain.Price{Currency: "USD", CacheRead: dec("-0.1")}},
	}
	for _, tc := range bad {
		if _, err := domain.Estimate(tc.u, tc.p); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", tc.name, err)
		}
	}
	huge := domain.Price{Currency: "USD", Input: money.MustParse("999999999999999999.99999999"), Output: money.MustParse("999999999999999999.99999999")}
	if _, err := domain.Estimate(domain.Usage{InputTokens: domain.MaxTokens, OutputTokens: domain.MaxTokens, Reported: true}, huge); !errors.Is(err, money.ErrOverflow) {
		t.Fatalf("overflow: %v", err)
	}
	// The largest counts at a large but representable price still fit.
	big := domain.Price{Currency: "USD", Input: money.MustParse("1000000"), Output: money.MustParse("1000000")}
	got, err := domain.Estimate(domain.Usage{InputTokens: domain.MaxTokens, OutputTokens: domain.MaxTokens, CacheReadTokens: domain.MaxTokens, CacheWriteTokens: domain.MaxTokens, Reported: true}, big)
	if err != nil || !got.Amount.Equal(money.MustParse("4000000000")) {
		t.Fatalf("large: %v %v", got, err)
	}
}

// TestUsageTotal: the total is the four counts summed.
//
// Covers: F986
func TestUsageTotal(t *testing.T) {
	u := domain.Usage{InputTokens: 1, OutputTokens: 2, CacheReadTokens: 3, CacheWriteTokens: 4, Reported: true}
	if u.Total() != 10 || u.Validate() != nil {
		t.Fatalf("total %d, %v", u.Total(), u.Validate())
	}
}

// TestParseMonth: a report month is a UTC calendar month, YYYY-MM only.
//
// Covers: F988
func TestParseMonth(t *testing.T) {
	m, err := domain.ParseMonth("2026-12")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Start.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) || !m.End.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		m.Start.Location() != time.UTC || m.String() != "2026-12" {
		t.Fatalf("month %+v", m)
	}
	if m, _ := domain.ParseMonth("2028-02"); m.End.Sub(m.Start) != 29*24*time.Hour {
		t.Fatalf("leap February: %v", m.End.Sub(m.Start))
	}
	for _, bad := range []string{"", "2026-13", "2026-00", "2026-1", "26-01", "2026-01-01", "2026/01", " 2026-01"} {
		if _, err := domain.ParseMonth(bad); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// TestRecordValidate: a usage row fits pc.model_usage, and an UNKNOWN call
// carries no usage (D825).
//
// Covers: F988, HR-693
func TestRecordValidate(t *testing.T) {
	ok := domain.Record{
		ID: ids.NewV7(), TransactionID: ids.NewV7(), ConnectionID: ids.NewV7(),
		Operation: "anthropic.messages.create", Model: "claude-x", Outcome: domain.OutcomeAccepted,
		Usage: domain.Usage{InputTokens: 10, OutputTokens: 2, Reported: true},
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	long := make([]byte, domain.MaxModelLength+1)
	for i := range long {
		long[i] = 'm'
	}
	for name, mutate := range map[string]func(*domain.Record){
		"no transaction":     func(r *domain.Record) { r.TransactionID = ids.UUID{} },
		"no connection":      func(r *domain.Record) { r.ConnectionID = ids.UUID{} },
		"no operation":       func(r *domain.Record) { r.Operation = "" },
		"long model":         func(r *domain.Record) { r.Model = string(long) },
		"unknown outcome":    func(r *domain.Record) { r.Outcome = "DONE" },
		"unknown with usage": func(r *domain.Record) { r.Outcome = domain.OutcomeUnknown },
		"negative estimate": func(r *domain.Record) {
			r.Estimate = &domain.Amount{Amount: money.MustParse("-1"), Currency: "USD"}
		},
	} {
		r := ok
		mutate(&r)
		if err := r.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	unknown := ok
	unknown.Outcome, unknown.Usage = domain.OutcomeUnknown, domain.Usage{}
	if err := unknown.Validate(); err != nil {
		t.Fatalf("unknown without usage: %v", err)
	}
}

// TestBuildRows: rows keep the store's order, total the four counts, sum
// estimates per currency sorted by currency, and label keys.
//
// Covers: F988, HR-698
func TestBuildRows(t *testing.T) {
	usd := func(s string) domain.Amount { return domain.Amount{Amount: money.MustParse(s), Currency: "USD"} }
	eur := func(s string) domain.Amount { return domain.Amount{Amount: money.MustParse(s), Currency: "EUR"} }
	rows, err := domain.BuildRows([]domain.Group{
		{Key: "", Calls: 2, UnreportedCalls: 1, InputTokens: 5},
		{
			Key: "team-a", Calls: 3, UnknownCalls: 1, InputTokens: 1, OutputTokens: 2, CacheReadTokens: 3, CacheWriteTokens: 4,
			Estimates: []domain.Amount{usd("0.1"), eur("1"), usd("0.25")},
		},
		{Key: "big", InputTokens: math.MaxInt64, OutputTokens: 1},
	}, map[string]string{"team-a": "Payments"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].Label != "" || rows[0].TotalTokens != 5 || len(rows[0].Estimates) != 0 {
		t.Fatalf("row 0 %+v", rows[0])
	}
	r := rows[1]
	if r.Label != "Payments" || r.TotalTokens != 10 || len(r.Estimates) != 2 ||
		r.Estimates[0].Currency != "EUR" || r.Estimates[1].Currency != "USD" || !r.Estimates[1].Amount.Equal(money.MustParse("0.35")) {
		t.Fatalf("row 1 %+v", r)
	}
	if rows[2].Label != "big" || rows[2].TotalTokens != math.MaxInt64 {
		t.Fatalf("row 2 total %d", rows[2].TotalTokens)
	}
	if _, err := domain.BuildRows([]domain.Group{{Key: "x", Calls: -1}}, nil); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("negative sum: %v", err)
	}
	if _, err := domain.BuildRows([]domain.Group{{Key: "x", Estimates: []domain.Amount{usd("-1")}}}, nil); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("negative estimate: %v", err)
	}
}

// TestCursor: page tokens round-trip every key, the empty key included,
// and refuse anything this server did not make.
//
// Covers: F988
func TestCursor(t *testing.T) {
	for _, key := range []string{"", "claude-x", "0198f2a0-0000-7000-8000-000000000000"} {
		got, after, err := domain.DecodeCursor(domain.EncodeCursor(key))
		if err != nil || !after || got != key {
			t.Fatalf("%q: %q %v %v", key, got, after, err)
		}
	}
	if k, after, err := domain.DecodeCursor(""); err != nil || after || k != "" {
		t.Fatalf("first page: %q %v %v", k, after, err)
	}
	long := make([]byte, domain.MaxModelLength+1)
	for i := range long {
		long[i] = 'a'
	}
	for _, bad := range []string{"!", "eA", domain.EncodeCursor(string(long)), "_w"} {
		if _, _, err := domain.DecodeCursor(bad); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if domain.PageSize(0) != domain.DefaultPageSize || domain.PageSize(500) != domain.MaxPageSize || domain.PageSize(7) != 7 {
		t.Fatal("page sizes")
	}
}
