// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"slices"
	"unicode/utf8"
)

// TypeQueryFilter is a structured row filter (G0 M14 D9): a list of at
// most MaxPredicates predicates over identifier columns, which the gateway
// turns into parameterised SQL and never into text. Policies cannot see it
// (columns are bounded by identifier_list params instead).
const TypeQueryFilter ParamType = "query_filter"

// Query filter limits and operators (D9).
const (
	MaxPredicates     = 20
	MaxPredicateValue = 256
	MaxInValues       = 100
)

// FilterOps are the predicate operators: eq ne lt le gt ge take a value,
// in takes values, is_null and not_null take neither, prefix takes a value.
var FilterOps = []string{"eq", "ne", "lt", "le", "gt", "ge", "in", "is_null", "not_null", "prefix"}

// columnRe is a filter column: a lower-case identifier, never quoted.
var columnRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Predicate is one filter predicate.
type Predicate struct {
	Column string   `json:"column"`
	Op     string   `json:"op"`
	Value  *string  `json:"value,omitzero"`
	Values []string `json:"values,omitzero"`
}

// decodeFilter strictly decodes a query filter's canonical JSON: unknown
// members, a value where the operator takes none, a missing one, a non-
// string value, an over-long value or list, or too many predicates are
// refused (HR-100).
func decodeFilter(raw jsontext.Value) ([]Predicate, error) {
	var ps []Predicate
	if err := json.Unmarshal(raw, &ps, json.RejectUnknownMembers(true)); err != nil || ps == nil {
		return nil, fmt.Errorf("must be a list of predicates {column, op, value|values}")
	}
	return ps, checkFilter(ps)
}

// checkFilter checks decoded predicates.
func checkFilter(ps []Predicate) error {
	if len(ps) > MaxPredicates {
		return fmt.Errorf("at most %d predicates", MaxPredicates)
	}
	for i, p := range ps {
		at := fmt.Sprintf("predicate %d", i)
		if !columnRe.MatchString(p.Column) || !slices.Contains(FilterOps, p.Op) {
			return fmt.Errorf("%s: a lower-case column and one of %v", at, FilterOps)
		}
		switch p.Op {
		case "is_null", "not_null":
			if p.Value != nil || p.Values != nil {
				return fmt.Errorf("%s: %s takes no value", at, p.Op)
			}
		case "in":
			if p.Value != nil || len(p.Values) == 0 || len(p.Values) > MaxInValues {
				return fmt.Errorf("%s: in takes 1..%d values", at, MaxInValues)
			}
			for _, v := range p.Values {
				if err := filterValue(v); err != nil {
					return fmt.Errorf("%s: %w", at, err)
				}
			}
		default:
			if p.Value == nil || p.Values != nil {
				return fmt.Errorf("%s: %s takes one value", at, p.Op)
			}
			if err := filterValue(*p.Value); err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
		}
	}
	return nil
}

// filterValue is a scalar of at most MaxPredicateValue bytes of valid UTF-8
// without control characters.
func filterValue(v string) error {
	if len(v) > MaxPredicateValue || !utf8.ValidString(v) {
		return fmt.Errorf("a value is at most %d bytes of UTF-8", MaxPredicateValue)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("a value holds a control character")
		}
	}
	return nil
}
