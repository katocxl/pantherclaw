// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgdispatch

import (
	"fmt"
	"strconv"
	"strings"
)

// Dialect is the SQL a statement is written in (G0 M31 D962). The zero
// value is Postgres. The same manifest, access and checks build both: only
// identifier quoting, placeholders, casts and the value expressions differ.
type Dialect int

const (
	// DialectPostgres is what a postgres connection runs (pgx, $n
	// placeholders, read-only transaction).
	DialectPostgres Dialect = iota
	// DialectSnowflake is what a snowflake connection sends to the
	// Snowflake SQL API: ? placeholders, each bound as TEXT and cast in
	// SQL; identifiers in upper case, as Snowflake stores unquoted ones.
	DialectSnowflake
)

// snowflakeType is the Snowflake type each column type is cast to.
// Snowflake has no uuid: a uuid column is a VARCHAR holding the canonical
// spelling, which checkValue requires. DECFLOAT keeps a numeric value's
// digits, as Postgres's numeric does.
var snowflakeType = map[ColumnType]string{
	TypeText:        "VARCHAR",
	TypeInt:         "INTEGER",
	TypeBigint:      "BIGINT",
	TypeNumeric:     "DECFLOAT",
	TypeBool:        "BOOLEAN",
	TypeDate:        "DATE",
	TypeTimestamptz: "TIMESTAMP_TZ",
	TypeUUID:        "VARCHAR",
}

// quoteUpper is quote for Snowflake: each manifest identifier (identRe,
// lower case) upper-cased, so a quoted name matches what an unquoted one
// in the customer's DDL created.
func quoteUpper(parts ...string) string {
	up := make([]string, len(parts))
	for i, p := range parts {
		up[i] = strings.ToUpper(p)
	}
	return quote(up...)
}

// ident quotes a qualified identifier in the builder's dialect.
func (b *builder) ident(parts ...string) string {
	if b.d == DialectSnowflake {
		return quoteUpper(parts...)
	}
	return quote(parts...)
}

// sel is a value expression of type t as the statement returns it: text
// cut to MaxValueChars+1 characters. Snowflake spells dates and times with
// a fixed format, never the session's.
func (b *builder) sel(expr string, t ColumnType) string {
	if b.d != DialectSnowflake {
		return selected(expr)
	}
	n := strconv.Itoa(MaxValueChars + 1)
	switch t { //nolint:exhaustive // only dates and times take a fixed format
	case TypeDate:
		return "LEFT(TO_VARCHAR(" + expr + ", 'YYYY-MM-DD'), " + n + ")"
	case TypeTimestamptz:
		return "LEFT(TO_VARCHAR(" + expr + `, 'YYYY-MM-DD"T"HH24:MI:SS.FF9TZH:TZM'), ` + n + ")"
	}
	return "LEFT(TO_VARCHAR(" + expr + "), " + n + ")"
}

// typed is one bound value cast to t: the value is always bound as text.
func (b *builder) typed(v string, t ColumnType) string {
	if b.d == DialectSnowflake {
		return "CAST(" + b.arg(v) + " AS " + snowflakeType[t] + ")"
	}
	return b.arg(v) + "::text::" + sqlType[t]
}

// anyOf is the predicate col IN the values, each cast to t.
func (b *builder) anyOf(col string, values []string, t ColumnType) string {
	if b.d == DialectSnowflake {
		parts := make([]string, len(values))
		for i, v := range values {
			parts[i] = b.typed(v, t)
		}
		return col + " IN (" + strings.Join(parts, ", ") + ")"
	}
	return fmt.Sprintf("%s = ANY(%s::text[]::%s[])", col, b.arg(append([]string{}, values...)), sqlType[t])
}

// like is the predicate col LIKE the pattern, backslash the escape.
func (b *builder) like(col, pattern string) string {
	if b.d == DialectSnowflake {
		// In a Snowflake string literal a backslash escapes: '\\' is one.
		return fmt.Sprintf(`%s LIKE %s ESCAPE '\\'`, col, b.arg(pattern))
	}
	return fmt.Sprintf(`%s LIKE %s::text ESCAPE E'\\'`, col, b.arg(pattern))
}

// Bindings are a Snowflake statement's arguments as the SQL API takes
// them: "1", "2", … each {"type":"TEXT","value":…}.
func (s *Statement) Bindings() (map[string]Binding, error) {
	out := make(map[string]Binding, len(s.Args))
	for i, a := range s.Args {
		v, ok := a.(string)
		if !ok {
			return nil, fmt.Errorf("pgdispatch: argument %d is not text", i+1)
		}
		out[strconv.Itoa(i+1)] = Binding{Type: "TEXT", Value: v}
	}
	return out, nil
}

// Binding is one bound value of the Snowflake SQL API.
type Binding struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
