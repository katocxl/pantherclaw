// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/base64"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

// Group is one key's sums over a month, as the store adds them up: calls,
// token counts and, per currency, the sum of the rows' estimates.
type Group struct {
	Key              string
	Calls            int64
	UnreportedCalls  int64
	UnknownCalls     int64
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	Estimates        []Amount
}

// Row is one row of the monthly token report (D825).
type Row struct {
	Group
	// Label names the key for people; the key itself when nothing names it.
	Label       string
	TotalTokens int64
}

// BuildRows turns the store's groups into report rows, in the groups'
// order: the total of the four counts (capped at math.MaxInt64 rather than
// wrapping) and one estimate per currency, sorted by currency. labels name
// the keys (teams, agents, connections); a key without a label is its own.
func BuildRows(groups []Group, labels map[string]string) ([]Row, error) {
	out := make([]Row, 0, len(groups))
	for _, g := range groups {
		for _, n := range []int64{g.Calls, g.UnreportedCalls, g.UnknownCalls, g.InputTokens, g.OutputTokens, g.CacheReadTokens, g.CacheWriteTokens} {
			if n < 0 {
				return nil, invalid("report sums are not negative")
			}
		}
		r := Row{Group: g, Label: g.Key, TotalTokens: addCapped(g.InputTokens, g.OutputTokens, g.CacheReadTokens, g.CacheWriteTokens)}
		if l, ok := labels[g.Key]; ok && l != "" {
			r.Label = l
		}
		est, err := mergeEstimates(g.Estimates)
		if err != nil {
			return nil, err
		}
		r.Estimates = est
		out = append(out, r)
	}
	return out, nil
}

func addCapped(ns ...int64) int64 {
	var t int64
	for _, n := range ns {
		if t > math.MaxInt64-n {
			return math.MaxInt64
		}
		t += n
	}
	return t
}

// mergeEstimates sums estimates by currency, sorted by currency.
func mergeEstimates(in []Amount) ([]Amount, error) {
	var out []Amount
	for _, m := range in {
		if m.Amount.Sign() < 0 {
			return nil, invalid("estimates are not negative")
		}
		i := slices.IndexFunc(out, func(o Amount) bool { return o.Currency == m.Currency })
		if i < 0 {
			out = append(out, m)
			continue
		}
		sum, err := out[i].Amount.Add(m.Amount)
		if err != nil {
			return nil, err
		}
		out[i].Amount = sum
	}
	slices.SortFunc(out, func(a, b Amount) int { return strings.Compare(string(a.Currency), string(b.Currency)) })
	return out, nil
}

// Report paging. Rows are ordered by key; the token is the last key of a
// page, so the empty key (calls without a team or agent) pages like any
// other.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
	maxKeyBytes     = MaxModelLength
	cursorPrefix    = "k"
)

// EncodeCursor is the page token after key.
func EncodeCursor(key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + key))
}

// DecodeCursor returns the key a page token continues after; after is
// false for the first page ("").
func DecodeCursor(token string) (key string, after bool, err error) {
	if token == "" {
		return "", false, nil
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(b) > len(cursorPrefix)+maxKeyBytes || !utf8.Valid(b) {
		return "", false, invalid("page token")
	}
	key, ok := strings.CutPrefix(string(b), cursorPrefix)
	if !ok {
		return "", false, invalid("page token")
	}
	return key, true, nil
}

// PageSize is the rows a page holds: the default for 0, at most
// MaxPageSize.
func PageSize(n int32) int {
	if n <= 0 {
		return DefaultPageSize
	}
	return int(min(n, MaxPageSize))
}
