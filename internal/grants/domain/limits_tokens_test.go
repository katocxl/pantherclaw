// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"

	authdomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR693_TokenRuleShape: a token rule sets max_tokens (1..10^12, a
// canonical decimal string) and none of currency, limit and max_count; its
// grouping follows the owner as every budget's does (G0 M29 D821).
//
// Covers: F982, HR-693
func TestHR693_TokenRuleShape(t *testing.T) {
	good := map[string]struct {
		doc     string
		onGrant bool
	}{
		"task tokens on a grant":     {`{"budgets": [{"id": "model", "grouping": "task", "operations": ["anthropic.*"], "max_tokens": "200000", "period": "none"}]}`, true},
		"team tokens on a guardrail": {`{"budgets": [{"id": "team_month", "grouping": "team", "operations": ["openai.*", "anthropic.*"], "max_tokens": "1000000000000", "period": "month"}]}`, false},
		"beside a money rule":        {`{"budgets": [{"id": "m", "grouping": "org", "operations": ["a.b"], "max_tokens": "1", "period": "day"}, {"id": "usd", "grouping": "org", "operations": ["a.b"], "currency": "USD", "limit": "5", "period": "day"}]}`, false},
	}
	for name, tt := range good {
		if err := mustLimits(t, tt.doc).validate(tt.onGrant); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]struct {
		doc     string
		onGrant bool
	}{
		"tokens with a currency":           {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_tokens": "5", "currency": "USD", "limit": "1", "period": "day"}]}`, true},
		"tokens with a count":              {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_tokens": "5", "max_count": "1", "period": "day"}]}`, true},
		"zero tokens":                      {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_tokens": "0", "period": "day"}]}`, true},
		"too many tokens":                  {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_tokens": "1000000000001", "period": "day"}]}`, true},
		"tokens with a sign":               {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_tokens": "+5", "period": "day"}]}`, true},
		"tokens with a fraction":           {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_tokens": "5.0", "period": "day"}]}`, true},
		"tokens with leading zero":         {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_tokens": "05", "period": "day"}]}`, true},
		"task token budget on a guardrail": {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_tokens": "5", "period": "day"}]}`, false},
		"principal tokens on a grant":      {`{"budgets": [{"id": "a", "grouping": "principal", "operations": ["a.b"], "max_tokens": "5", "period": "day"}]}`, true},
		"tokens with an unknown period":    {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_tokens": "5", "period": "year"}]}`, true},
	}
	for name, tt := range bad {
		if err := mustLimits(t, tt.doc).validate(tt.onGrant); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: validate = %v", name, err)
		}
	}
	if _, err := DecodeLimits([]byte(`{"budgets": [{"id": "a", "max_tokens": 5}]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatal("a JSON number was accepted for max_tokens")
	}
	if n, err := ParseMaxTokens("x", "1000000000000"); err != nil || n != MaxTokensValue {
		t.Fatalf("largest cap: %d %v", n, err)
	}
	if authdomain.ReasonTokenBudgetExhausted != ReasonTokenBudgetExhausted {
		t.Fatal("the token budget reason differs between grants and authority")
	}
}

// TestHR693_TokenRulesSkipMoneyDebits: a token rule never makes a money or
// count debit; actions that are not model calls skip it (G0 M29 D821).
//
// Covers: F982, HR-693
func TestHR693_TokenRulesSkipMoneyDebits(t *testing.T) {
	root := rootGrant(t, refundBounds)
	root.Limits = mustLimits(t, `{"budgets": [{"id": "tokens", "grouping": "task", "operations": ["payments.*"], "max_tokens": "10", "period": "none"}]}`)
	plan, f := (Chain{Grants: []Grant{root}}).Debits(refund("1", "USD", "duplicate", mondayNoon), DebitContext{Now: mondayNoon, RunID: ids.NewV7(), Principal: alice})
	if f != nil || len(plan.Budgets) != 0 || len(plan.Counters) != 0 {
		t.Fatalf("a token rule debited a payment: %+v %+v", plan, f)
	}
}

// TestHR693_ReservedTokens: a model call reserves its max tokens times its
// choices plus a third of its request bytes, rounded up (G0 M29 D813).
//
// Covers: F982, HR-693
func TestHR693_ReservedTokens(t *testing.T) {
	cases := []struct{ max, choices, bytes, want int64 }{
		{1000, 1, 0, 1000},
		{1000, 1, 1, 1001},
		{1000, 1, 3, 1001},
		{1000, 1, 4, 1002},
		{1000, 4, 300, 4100},
		{1000, 0, 0, 1000}, // choices default to 1
		{-5, 1, 6, 2},
		{MaxTokensValue, 1_000_000_000, 1 << 62, MaxTokensValue*1_000_000 + (1<<62)/3 + 1},
	}
	for _, c := range cases {
		if got := ReservedTokens(c.max, c.choices, c.bytes); got != c.want {
			t.Errorf("ReservedTokens(%d, %d, %d) = %d, want %d", c.max, c.choices, c.bytes, got, c.want)
		}
	}
}

// TestHR693_TokenCapsOnlyNarrow: narrowing may lower a token cap, never
// raise or drop it (G0 M29 D821).
//
// Covers: F982, HR-693
func TestHR693_TokenCapsOnlyNarrow(t *testing.T) {
	base := mustLimits(t, `{"budgets": [{"id": "tokens", "grouping": "task", "operations": ["anthropic.*"], "max_tokens": "1000", "period": "none"}]}`)
	lower := mustLimits(t, `{"budgets": [{"id": "tokens", "grouping": "task", "operations": ["anthropic.*"], "max_tokens": "10", "period": "none"}]}`)
	got, err := NarrowLimits(base, lower)
	if err != nil || got.Budgets[0].MaxTokens != "10" {
		t.Fatalf("lower: %+v %v", got, err)
	}
	for name, doc := range map[string]string{
		"higher":  `{"budgets": [{"id": "tokens", "grouping": "task", "operations": ["anthropic.*"], "max_tokens": "1001", "period": "none"}]}`,
		"dropped": `{"budgets": [{"id": "tokens", "grouping": "task", "operations": ["anthropic.*"], "max_count": "1", "period": "none"}]}`,
		"widened": `{"budgets": [{"id": "tokens", "grouping": "task", "operations": ["openai.*"], "max_tokens": "10", "period": "none"}]}`,
	} {
		if _, err := NarrowLimits(base, mustLimits(t, doc)); !errors.Is(err, ErrOutside) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
