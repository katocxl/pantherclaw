// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgdispatch

import (
	"strings"
	"testing"
)

// TestHR726_ASnowflakeReadIsBuiltFromTheAllowList: a Snowflake read names
// only allow-listed columns, upper-cased and quoted, with every value a
// typed ? bind, never text in the statement.
//
// Covers: HR-726
func TestHR726_ASnowflakeReadIsBuiltFromTheAllowList(t *testing.T) {
	st, err := BuildRows(shop(), Rows{
		Table: "shop.orders", Columns: []string{"id", "status"},
		Filters: []Filter{{Column: "status", Op: OpEq, Value: ptr("paid'); DROP TABLE x; --")}, {Column: "id", Op: OpIn, Values: []string{"1", "2"}}},
		Limit:   5, Dialect: DialectSnowflake,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `SELECT LEFT(TO_VARCHAR("SHOP"."ORDERS"."ID"), 4097), LEFT(TO_VARCHAR("SHOP"."ORDERS"."STATUS"), 4097) FROM "SHOP"."ORDERS"` +
		` WHERE ("SHOP"."ORDERS"."STATUS" = CAST(? AS VARCHAR)) AND ("SHOP"."ORDERS"."ID" IN (CAST(? AS BIGINT), CAST(? AS BIGINT))) LIMIT 6`
	if st.SQL != want || strings.Contains(st.SQL, "DROP") {
		t.Fatalf("SQL\n got %s\nwant %s", st.SQL, want)
	}
	b, err := st.Bindings()
	if err != nil || len(b) != 3 || b["1"] != (Binding{Type: "TEXT", Value: "paid'); DROP TABLE x; --"}) || b["3"].Value != "2" {
		t.Fatalf("bindings %v %v", b, err)
	}
}

// TestT334_ASnowflakeReadPastItsAllowListIsRefused: a table or column the
// manifest does not list, a table outside the decision's tables and a
// secret column are never read (T-334).
//
// Covers: HR-726, T-334
func TestT334_ASnowflakeReadPastItsAllowListIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		q    Rows
		code string
	}{
		"unlisted table":  {Rows{Table: "shop.payroll", Columns: []string{"id"}}, ""},
		"unlisted column": {Rows{Table: "shop.orders", Columns: []string{"card_number"}}, CodeColumnNotAllowed},
		"other decision":  {Rows{Table: "shop.orders", Columns: []string{"id"}, Access: Access{Tables: []string{"shop.customers"}}}, CodeTableNotAllowed},
	} {
		c.q.Dialect = DialectSnowflake
		_, err := BuildRows(shop(), c.q)
		if err == nil || (c.code != "" && CodeOf(err) != c.code) {
			t.Errorf("%s: %v (%s)", name, err, CodeOf(err))
		}
	}
	st, err := BuildRows(shop(), Rows{Table: "shop.customers", Columns: []string{"id", "ssn"}, Dialect: DialectSnowflake})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(st.SQL, `"SSN"`) {
		t.Fatalf("a secret column was read: %s", st.SQL)
	}
}
