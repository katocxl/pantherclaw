// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgdispatch

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// shop is the D19 fixture manifest.
func shop() Manifest {
	return Manifest{Tables: []Table{
		{Schema: "shop", Name: "customers", ScopeKey: "customer", ScopeColumn: "id", Columns: []Column{
			{Name: "id", Type: TypeBigint, Class: ClassPublic},
			{Name: "name", Type: TypeText, Class: ClassPII},
			{Name: "email", Type: TypeText, Class: ClassPII},
			{Name: "tier", Type: TypeText, Class: ClassPublic},
			{Name: "ssn", Type: TypeText, Class: ClassSecret},
		}},
		{Schema: "shop", Name: "orders", ScopeKey: "customer", ScopeColumn: "customer_id", MaxRows: 50, Columns: []Column{
			{Name: "id", Type: TypeBigint, Class: ClassPublic},
			{Name: "customer_id", Type: TypeBigint, Class: ClassPublic},
			{Name: "amount", Type: TypeNumeric, Class: ClassInternal},
			{Name: "status", Type: TypeText, Class: ClassPublic},
			{Name: "placed", Type: TypeTimestamptz, Class: ClassPublic},
			{Name: "paid", Type: TypeBool, Class: ClassPublic},
		}},
		{Schema: "support", Name: "tickets", Columns: []Column{
			{Name: "id", Type: TypeUUID, Class: ClassPublic},
			{Name: "customer_id", Type: TypeBigint, Class: ClassPublic},
			{Name: "subject", Type: TypeText, Class: ClassInternal},
			{Name: "opened", Type: TypeDate, Class: ClassPublic},
		}},
	}}
}

func ptr(s string) *string { return &s }

func code(t *testing.T, err error, want string) {
	t.Helper()
	if got := CodeOf(err); got != want {
		t.Fatalf("error %v: code %q, want %q", err, got, want)
	}
}

func TestManifest_Validation(t *testing.T) {
	n, err := shop().Normalized()
	if err != nil {
		t.Fatal(err)
	}
	if n.MaxRows != DefaultMaxRows || n.StatementTimeoutMS != DefaultStatementTimeout ||
		n.MaxResultBytes != DefaultMaxResultBytes || n.MinGroupSize != DefaultMinGroupSize {
		t.Fatalf("defaults not filled: %+v", n)
	}
	for name, mut := range map[string]func(*Manifest){
		"no tables":            func(m *Manifest) { m.Tables = nil },
		"max_rows too high":    func(m *Manifest) { m.MaxRows = 1001 },
		"max_rows negative":    func(m *Manifest) { m.MaxRows = -1 },
		"timeout too high":     func(m *Manifest) { m.StatementTimeoutMS = 30001 },
		"result bytes too big": func(m *Manifest) { m.MaxResultBytes = 4<<20 + 1 },
		"min group 1":          func(m *Manifest) { m.MinGroupSize = 1 },
		"upper-case schema":    func(m *Manifest) { m.Tables[0].Schema = "Shop" },
		"quoted name":          func(m *Manifest) { m.Tables[0].Name = `customers"` },
		"dotted name":          func(m *Manifest) { m.Tables[0].Name = "a.b" },
		"long name":            func(m *Manifest) { m.Tables[0].Name = strings.Repeat("a", 64) },
		"digit first":          func(m *Manifest) { m.Tables[0].Columns[0].Name = "1id" },
		"column with space":    func(m *Manifest) { m.Tables[0].Columns[0].Name = "id x" },
		"jsonb column":         func(m *Manifest) { m.Tables[0].Columns[0].Type = "jsonb" },
		"bytea column":         func(m *Manifest) { m.Tables[0].Columns[0].Type = "bytea" },
		"array column":         func(m *Manifest) { m.Tables[0].Columns[0].Type = "text[]" },
		"unknown class":        func(m *Manifest) { m.Tables[0].Columns[0].Class = "confidential" },
		"duplicate column":     func(m *Manifest) { m.Tables[0].Columns[1].Name = "id" },
		"duplicate table":      func(m *Manifest) { m.Tables[1].Name = "customers" },
		"no columns":           func(m *Manifest) { m.Tables[2].Columns = nil },
		"scope key alone":      func(m *Manifest) { m.Tables[0].ScopeColumn = "" },
		"scope column alone":   func(m *Manifest) { m.Tables[2].ScopeColumn = "customer_id" },
		"scope column unknown": func(m *Manifest) { m.Tables[0].ScopeColumn = "nope" },
		"bad scope key":        func(m *Manifest) { m.Tables[0].ScopeKey = "Customer" },
		"table max_rows":       func(m *Manifest) { m.Tables[0].MaxRows = 1001 },
	} {
		t.Run(name, func(t *testing.T) {
			m := shop()
			mut(&m)
			_, err := m.Normalized()
			code(t, err, CodeManifestInvalid)
		})
	}
}

func TestManifest_TableLookupIsExact(t *testing.T) {
	m := shop()
	if tb, err := m.Table("shop.customers"); err != nil || tb.Name != "customers" {
		t.Fatalf("lookup: %v %v", tb, err)
	}
	for _, ref := range []string{
		"shop.Customers", "SHOP.customers", `"shop"."customers"`, "shop.customers ", "shop.customers;",
		"customers", "public.customers", "shop.customers.id", "shop..customers", "", "pg_catalog.pg_authid",
	} {
		_, err := m.Table(ref)
		code(t, err, CodeTableNotAllowed)
	}
}

func TestBuildRows_Golden(t *testing.T) {
	st, err := BuildRows(shop(), Rows{
		Table:   "shop.orders",
		Columns: []string{"id", "amount", "status"},
		Filters: []Filter{
			{Column: "status", Op: OpEq, Value: ptr("paid")},
			{Column: "amount", Op: OpGe, Value: ptr("10.50")},
			{Column: "id", Op: OpIn, Values: []string{"1", "2"}},
			{Column: "placed", Op: OpNotNull},
			{Column: "status", Op: OpPrefix, Value: ptr("re")},
		},
		OrderBy: []Order{{Column: "placed", Desc: true}, {Column: "id"}},
		Limit:   20,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `SELECT "id"::text, "amount"::text, "status"::text FROM "shop"."orders"` +
		` WHERE ("status" = $1::text::text) AND ("amount" >= $2::text::numeric) AND ("id" = ANY($3::text[]::bigint[]))` +
		` AND ("placed" IS NOT NULL) AND ("status" LIKE $4::text ESCAPE E'\\')` +
		` ORDER BY "placed" DESC, "id" ASC LIMIT 21`
	if st.SQL != want {
		t.Fatalf("SQL\n got %s\nwant %s", st.SQL, want)
	}
	wantArgs := []any{"paid", "10.50", []string{"1", "2"}, "re%"}
	if got := mustJSON(st.Args); got != mustJSON(wantArgs) {
		t.Fatalf("args %s, want %s", got, mustJSON(wantArgs))
	}
	if st.Limit != 20 || st.Selected() != 3 {
		t.Fatalf("limit %d selected %d", st.Limit, st.Selected())
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestBuildRows_Limits(t *testing.T) {
	m := shop()
	m.MaxRows = 100
	for _, c := range []struct {
		table          string
		request, clamp int
		want           int
	}{
		{"shop.customers", 0, 0, 100},
		{"shop.customers", 500, 0, 100},
		{"shop.customers", 7, 0, 7},
		{"shop.customers", 0, 9, 9},
		{"shop.customers", 30, 9, 9},
		{"shop.orders", 0, 0, 50}, // table max_rows
		{"shop.orders", 80, 60, 50},
		{"shop.orders", 80, 3, 3},
	} {
		st, err := BuildRows(m, Rows{Table: c.table, Columns: []string{"id"}, Limit: c.request, Clamp: c.clamp})
		if err != nil {
			t.Fatal(err)
		}
		if st.Limit != c.want || !strings.HasSuffix(st.SQL, " LIMIT "+itoa(c.want+1)) {
			t.Errorf("%+v: limit %d, SQL %s", c, st.Limit, st.SQL)
		}
	}
	_, err := BuildRows(m, Rows{Table: "shop.orders", Columns: []string{"id"}, Limit: -1})
	code(t, err, CodeQueryInvalid)
}

func itoa(n int) string { return strconv.Itoa(n) }

// TestBuildRows_InjectionThroughIdentifiers: a table, column, sort key or
// filter column that is not exactly a manifest identifier is refused, so
// nothing an agent spells reaches the SQL text as an identifier (HR-307).
func TestBuildRows_InjectionThroughIdentifiers(t *testing.T) {
	evil := []string{
		`id"; DROP TABLE shop.customers; --`, `id::text`, `"id"`, `ID`, `id,ssn`, `id ssn`, `(select 1)`,
		`id--`, `id/*`, `*`, `id\`, "id\x00", `ssn) OR (1=1`, `pg_sleep(10)`, `customers.id`, ``,
	}
	for _, e := range evil {
		for name, q := range map[string]Rows{
			"column": {Table: "shop.customers", Columns: []string{e}},
			"filter": {Table: "shop.customers", Columns: []string{"id"}, Filters: []Filter{{Column: e, Op: OpEq, Value: ptr("1")}}},
			"order":  {Table: "shop.customers", Columns: []string{"id"}, OrderBy: []Order{{Column: e}}},
		} {
			_, err := BuildRows(shop(), q)
			code(t, err, CodeColumnNotAllowed)
			_ = name
		}
		_, err := BuildRows(shop(), Rows{Table: "shop." + e, Columns: []string{"id"}})
		code(t, err, CodeTableNotAllowed)
		_, err = BuildAggregate(shop(), Aggregate{Table: "shop.orders", GroupBy: []string{e}, Measures: []Measure{{"count", "*"}}})
		code(t, err, CodeColumnNotAllowed)
		_, err = BuildAggregate(shop(), Aggregate{Table: "shop.orders", Measures: []Measure{{"sum", e}}})
		if e == "*" {
			code(t, err, CodeQueryInvalid)
		} else {
			code(t, err, CodeColumnNotAllowed)
		}
	}
	for _, f := range []string{"count(*) ; --", "sum", "pg_sleep", "COUNT", "string_agg", "array_agg"} {
		if f == "sum" {
			continue
		}
		_, err := BuildAggregate(shop(), Aggregate{Table: "shop.orders", Measures: []Measure{{f, "amount"}}})
		code(t, err, CodeQueryInvalid)
		_, err = ParseMeasure(f + ":amount")
		code(t, err, CodeQueryInvalid)
	}
}

// TestBuildRows_InjectionThroughValues: values only ever travel as
// parameters; the SQL text never contains them, whatever they hold.
func TestBuildRows_InjectionThroughValues(t *testing.T) {
	values := []string{
		`' OR '1'='1`, `paid'); DELETE FROM shop.orders; --`, `$1`, `\'x`, `%`, `_`, `\`, `E'\x41'`,
		`'; COMMIT; UPDATE shop.orders SET status='x'; --`, `$$; DROP TABLE x; $$`, "a\nb", `"`, `;`,
	}
	for _, v := range values {
		st, err := BuildRows(shop(), Rows{
			Table:   "shop.orders",
			Columns: []string{"status"},
			Filters: []Filter{
				{Column: "status", Op: OpEq, Value: ptr(v)},
				{Column: "status", Op: OpPrefix, Value: ptr(v)},
				{Column: "status", Op: OpIn, Values: []string{v, "ok"}},
			},
		})
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		assertOnlyKnownTokens(t, st.SQL)
		if strings.Contains(st.SQL, v) && len(v) > 1 && v != "$1" {
			t.Fatalf("value %q appears in SQL %s", v, st.SQL)
		}
	}
	// A value of the wrong type never reaches the database's cast.
	for col, bad := range map[string][]string{
		"id":     {"1 OR 1=1", "1;", "0x10", "01", "1e3", "9223372036854775808", " 1", "1.0", "-0x1"},
		"amount": {"1e5", "NaN", "Infinity", "1,5", ".5", "1.", "--1", "1 "},
		"paid":   {"t", "TRUE", "yes", "1"},
		"placed": {"2026-10-17", "now", "2026-10-17 10:00:00", "epoch"},
	} {
		for _, v := range bad {
			_, err := BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id"}, Filters: []Filter{{Column: col, Op: OpEq, Value: ptr(v)}}})
			code(t, err, CodeQueryInvalid)
		}
	}
	for col, bad := range map[string][]string{
		"id":     {"A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11", "{a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11}", "a0eebc999c0b4ef8bb6d6bb9bd380a11"},
		"opened": {"2026-13-01", "2026-02-30", "26-10-17", "today", "2026-10-17T00:00:00Z"},
	} {
		for _, v := range bad {
			_, err := BuildRows(shop(), Rows{Table: "support.tickets", Columns: []string{"id"}, Filters: []Filter{{Column: col, Op: OpEq, Value: ptr(v)}}})
			code(t, err, CodeQueryInvalid)
		}
	}
	for _, v := range []string{strings.Repeat("a", MaxValueLength+1), "a\x00b", "\xff"} {
		_, err := BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id"}, Filters: []Filter{{Column: "status", Op: OpEq, Value: ptr(v)}}})
		code(t, err, CodeQueryInvalid)
	}
}

// tokenRe matches what built SQL may consist of: keywords, quoted manifest
// identifiers, placeholders with casts, operators and the fixed escape.
var tokenRe = regexp.MustCompile(`^(::text|SELECT|FROM|WHERE|AND|ORDER|BY|ASC|DESC|LIMIT|GROUP|HAVING|IS|NOT|NULL|ANY|LIKE|ESCAPE|E'\\\\'|"[a-z_][a-z0-9_]*"(\."[a-z_][a-z0-9_]*")?(::text)?|\$[0-9]+::text(\[\])?(::[a-z]+(\[\])?)?|count\(\*\)|(count|sum|avg|min|max)\("[a-z_][a-z0-9_]*"\)(::text)?|[(),]|=|<>|<|<=|>|>=|[0-9]+)$`)

func assertOnlyKnownTokens(t *testing.T, sql string) {
	t.Helper()
	s := strings.NewReplacer("(", " ( ", ")", " ) ", ",", " , ").Replace(sql)
	s = strings.ReplaceAll(s, "count ( * ) ", "count(*) ")
	for _, m := range []string{"count", "sum", "avg", "min", "max"} {
		s = regexp.MustCompile(m+` \( ("[a-z_0-9]+") \) (::text)?`).ReplaceAllString(s, m+`($1)$2 `)
	}
	for tok := range strings.FieldsSeq(s) {
		if !tokenRe.MatchString(tok) {
			t.Fatalf("unexpected token %q in %s", tok, sql)
		}
	}
}

func TestBuildRows_PrefixEscaping(t *testing.T) {
	for in, want := range map[string]string{
		"re":     "re%",
		"50%":    `50\%%`,
		"a_b":    `a\_b%`,
		`c:\dir`: `c:\\dir%`,
		`\%_`:    `\\\%\_%`,
		"":       "%",
	} {
		if got := LikePrefix(in); got != want {
			t.Errorf("LikePrefix(%q) = %q, want %q", in, got, want)
		}
	}
	_, err := BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id"}, Filters: []Filter{{Column: "amount", Op: OpPrefix, Value: ptr("1")}}})
	code(t, err, CodeQueryInvalid)
}

func TestBuildRows_FilterShapes(t *testing.T) {
	many := make([]string, MaxInValues+1)
	for i := range many {
		many[i] = "1"
	}
	for name, f := range map[string]Filter{
		"eq without value":   {Column: "id", Op: OpEq},
		"eq with values":     {Column: "id", Op: OpEq, Value: ptr("1"), Values: []string{"1"}},
		"in with value":      {Column: "id", Op: OpIn, Value: ptr("1")},
		"in empty":           {Column: "id", Op: OpIn, Values: []string{}},
		"in too many":        {Column: "id", Op: OpIn, Values: many},
		"is_null with value": {Column: "id", Op: OpIsNull, Value: ptr("1")},
		"unknown op":         {Column: "id", Op: "like", Value: ptr("1")},
		"raw sql op":         {Column: "id", Op: "= 1 OR 1 =", Value: ptr("1")},
	} {
		_, err := BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id"}, Filters: []Filter{f}})
		if CodeOf(err) != CodeQueryInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	fs := make([]Filter, MaxFilters+1)
	for i := range fs {
		fs[i] = Filter{Column: "id", Op: OpNotNull}
	}
	_, err := BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id"}, Filters: fs})
	code(t, err, CodeQueryInvalid)
	_, err = BuildRows(shop(), Rows{Table: "shop.orders"})
	code(t, err, CodeQueryInvalid)
	_, err = BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id", "id"}})
	code(t, err, CodeQueryInvalid)
	_, err = BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id"}, OrderBy: []Order{{Column: "id"}, {Column: "id", Desc: true}}})
	code(t, err, CodeQueryInvalid)
}

// TestBuildRows_Classes: a column whose class may not be read is never
// selected and comes back as a placeholder; it may not be filtered,
// sorted, grouped or measured either (D16, D20). Secret is never read.
func TestBuildRows_Classes(t *testing.T) {
	st, err := BuildRows(shop(), Rows{Table: "shop.customers", Columns: []string{"id", "email", "ssn"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(st.SQL, "ssn") || !strings.Contains(st.SQL, `"email"`) {
		t.Fatalf("no obligation: secret selected or pii dropped: %s", st.SQL)
	}
	st, err = BuildRows(shop(), Rows{Table: "shop.customers", Columns: []string{"id", "email", "ssn"}, Access: Access{Classes: []Class{ClassPublic}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(st.SQL, "email") || strings.Contains(st.SQL, "ssn") || st.Selected() != 1 {
		t.Fatalf("withheld columns selected: %s", st.SQL)
	}
	if st.Output[1].Redacted != ClassPII || st.Output[2].Redacted != ClassSecret {
		t.Fatalf("outputs %+v", st.Output)
	}
	// Even an obligation that names secret cannot make it readable.
	st, err = BuildRows(shop(), Rows{Table: "shop.customers", Columns: []string{"ssn"}, Access: Access{Classes: []Class{ClassSecret, ClassPII}}})
	if err != nil || strings.Contains(st.SQL, "ssn") || st.Selected() != 0 {
		t.Fatalf("secret read: %v %v", st, err)
	}
	pub := Access{Classes: []Class{ClassPublic}}
	for name, q := range map[string]Rows{
		"filter on pii":    {Table: "shop.customers", Columns: []string{"id"}, Access: pub, Filters: []Filter{{Column: "email", Op: OpPrefix, Value: ptr("a")}}},
		"sort on pii":      {Table: "shop.customers", Columns: []string{"id"}, Access: pub, OrderBy: []Order{{Column: "name"}}},
		"filter on secret": {Table: "shop.customers", Columns: []string{"id"}, Filters: []Filter{{Column: "ssn", Op: OpEq, Value: ptr("1")}}},
		"sort on secret":   {Table: "shop.customers", Columns: []string{"id"}, OrderBy: []Order{{Column: "ssn"}}},
		"null on secret":   {Table: "shop.customers", Columns: []string{"id"}, Filters: []Filter{{Column: "ssn", Op: OpIsNull}}},
	} {
		_, err := BuildRows(shop(), q)
		if CodeOf(err) != CodeColumnNotAllowed {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, q := range map[string]Aggregate{
		"group on secret":   {Table: "shop.customers", GroupBy: []string{"ssn"}, Measures: []Measure{{"count", "*"}}},
		"min of secret":     {Table: "shop.customers", Measures: []Measure{{"min", "ssn"}}},
		"count of secret":   {Table: "shop.customers", Measures: []Measure{{"count", "ssn"}}},
		"group on internal": {Table: "shop.orders", GroupBy: []string{"amount"}, Measures: []Measure{{"count", "*"}}, Access: pub},
		"sum of internal":   {Table: "shop.orders", Measures: []Measure{{"sum", "amount"}}, Access: pub},
	} {
		_, err := BuildAggregate(shop(), q)
		if CodeOf(err) != CodeColumnNotAllowed {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err = BuildRows(shop(), Rows{Table: "shop.customers", Columns: []string{"id"}, Access: Access{Classes: []Class{"everything"}}})
	code(t, err, CodeQueryInvalid)
}

// TestBuildRows_ColumnBound: the decision's column bound limits what the
// query may name anywhere.
func TestBuildRows_ColumnBound(t *testing.T) {
	acc := Access{Columns: []string{"id", "status"}}
	if _, err := BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id", "status"}, Access: acc}); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]Rows{
		"select": {Table: "shop.orders", Columns: []string{"id", "amount"}, Access: acc},
		"filter": {Table: "shop.orders", Columns: []string{"id"}, Access: acc, Filters: []Filter{{Column: "amount", Op: OpGt, Value: ptr("1")}}},
		"sort":   {Table: "shop.orders", Columns: []string{"id"}, Access: acc, OrderBy: []Order{{Column: "customer_id"}}},
	} {
		_, err := BuildRows(shop(), q)
		if CodeOf(err) != CodeColumnNotAllowed {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBuild_RecordScope(t *testing.T) {
	sc := &RecordScope{Key: "customer", Values: []string{"7", "9"}}
	st, err := BuildRows(shop(), Rows{
		Table: "shop.orders", Columns: []string{"id"}, Scope: sc,
		Filters: []Filter{{Column: "customer_id", Op: OpEq, Value: ptr("8")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `SELECT "id"::text FROM "shop"."orders" WHERE ("customer_id" = $1::text::bigint) AND ("customer_id" = ANY($2::text[]::bigint[])) LIMIT 51`
	if st.SQL != want {
		t.Fatalf("SQL\n got %s\nwant %s", st.SQL, want)
	}
	// The scope applies even when the agent may not read the scope column.
	st, err = BuildRows(shop(), Rows{Table: "shop.customers", Columns: []string{"tier"}, Scope: sc, Access: Access{Columns: []string{"tier"}}})
	if err != nil || !strings.Contains(st.SQL, `("id" = ANY($1::text[]::bigint[]))`) {
		t.Fatalf("scope: %v %v", st, err)
	}
	// An empty scope matches nothing; it is still applied.
	st, err = BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id"}, Scope: &RecordScope{Key: "customer"}})
	if err != nil || !strings.Contains(st.SQL, "ANY($1") {
		t.Fatalf("empty scope: %v %v", st, err)
	}
	for name, q := range map[string]Rows{
		"table without scope key": {Table: "support.tickets", Columns: []string{"id"}, Scope: sc},
		"other key":               {Table: "shop.orders", Columns: []string{"id"}, Scope: &RecordScope{Key: "region", Values: []string{"7"}}},
		"value of another type":   {Table: "shop.orders", Columns: []string{"id"}, Scope: &RecordScope{Key: "customer", Values: []string{"7 OR 1=1"}}},
		"too many values":         {Table: "shop.orders", Columns: []string{"id"}, Scope: &RecordScope{Key: "customer", Values: make([]string, MaxScopeValues+1)}},
	} {
		_, err := BuildRows(shop(), q)
		if CodeOf(err) != CodeScopeUnsupported {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err = BuildAggregate(shop(), Aggregate{Table: "support.tickets", Measures: []Measure{{"count", "*"}}, Scope: sc})
	code(t, err, CodeScopeUnsupported)
}

func TestBuildAggregate_Golden(t *testing.T) {
	st, err := BuildAggregate(shop(), Aggregate{
		Table:    "shop.orders",
		GroupBy:  []string{"status", "paid"},
		Measures: []Measure{{"count", "*"}, {"sum", "amount"}, {"avg", "amount"}, {"max", "placed"}, {"count", "id"}},
		Filters:  []Filter{{Column: "paid", Op: OpEq, Value: ptr("true")}},
		Scope:    &RecordScope{Key: "customer", Values: []string{"7"}},
		Limit:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `SELECT "status"::text, "paid"::text, count(*)::text, sum("amount")::text, avg("amount")::text, max("placed")::text, count("id")::text` +
		` FROM "shop"."orders" WHERE ("paid" = $1::text::boolean) AND ("customer_id" = ANY($2::text[]::bigint[]))` +
		` GROUP BY "status", "paid" HAVING count(*) >= 5 ORDER BY "status", "paid" LIMIT 11`
	if st.SQL != want {
		t.Fatalf("SQL\n got %s\nwant %s", st.SQL, want)
	}
	assertOnlyKnownTokens(t, st.SQL)
	types := []ColumnType{TypeText, TypeBool, TypeBigint, TypeNumeric, TypeNumeric, TypeTimestamptz, TypeBigint}
	for i, o := range st.Output {
		if o.Type != types[i] || o.Redacted != "" {
			t.Errorf("output %d %+v, want type %s", i, o, types[i])
		}
	}
	if st.Output[3].Name != "sum:amount" {
		t.Errorf("label %s", st.Output[3].Name)
	}
}

// TestBuildAggregate_SmallGroupsSuppressed: every aggregate, grouped or
// not, drops groups below min_group_size in the database (HR-312).
func TestBuildAggregate_SmallGroupsSuppressed(t *testing.T) {
	m := shop()
	m.MinGroupSize = 3
	st, err := BuildAggregate(m, Aggregate{Table: "shop.orders", Measures: []Measure{{"sum", "amount"}}})
	if err != nil {
		t.Fatal(err)
	}
	if st.SQL != `SELECT sum("amount")::text FROM "shop"."orders" HAVING count(*) >= 3 LIMIT 51` {
		t.Fatalf("SQL %s", st.SQL)
	}
	for name, q := range map[string]Aggregate{
		"no measures":       {Table: "shop.orders", GroupBy: []string{"status"}},
		"sum of text":       {Table: "shop.orders", Measures: []Measure{{"sum", "status"}}},
		"avg of bool":       {Table: "shop.orders", Measures: []Measure{{"avg", "paid"}}},
		"min of bool":       {Table: "shop.orders", Measures: []Measure{{"min", "paid"}}},
		"sum of *":          {Table: "shop.orders", Measures: []Measure{{"sum", "*"}}},
		"duplicate measure": {Table: "shop.orders", Measures: []Measure{{"count", "*"}, {"count", "*"}}},
		"duplicate group":   {Table: "shop.orders", GroupBy: []string{"status", "status"}, Measures: []Measure{{"count", "*"}}},
	} {
		_, err := BuildAggregate(m, q)
		if CodeOf(err) != CodeQueryInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseFilters(t *testing.T) {
	fs, err := ParseFilters([]byte(`[{"column":"status","op":"eq","value":"paid"},{"column":"id","op":"in","values":[1,2,"3"]},{"column":"paid","op":"eq","value":true},{"column":"placed","op":"is_null"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if *fs[0].Value != "paid" || !slices.Equal(fs[1].Values, []string{"1", "2", "3"}) || *fs[2].Value != "true" || fs[3].Value != nil {
		t.Fatalf("parsed %+v", fs)
	}
	if fs, err := ParseFilters(nil); err != nil || fs != nil {
		t.Fatalf("empty: %v %v", fs, err)
	}
	many := "[" + strings.Repeat(`{"column":"id","op":"is_null"},`, MaxFilters) + `{"column":"id","op":"is_null"}]`
	for _, raw := range []string{
		`{"column":"id"}`,
		`[{"column":"id","op":"eq","value":"1","sql":"1=1"}]`,
		`[{"column":"id","op":"eq","value":null}]`,
		`[{"column":"id","op":"eq","value":{"a":1}}]`,
		`[{"column":"id","op":"eq","value":[1]}]`,
		`[{"column":"id","op":"in","values":[null]}]`,
		`[] []`,
		`[{"column":"id","op":"eq","value":"1"}] x`,
		many,
	} {
		_, err := ParseFilters([]byte(raw))
		if CodeOf(err) != CodeQueryInvalid {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestParseOrderAndMeasure(t *testing.T) {
	if o, err := ParseOrder("placed:desc"); err != nil || o != (Order{"placed", true}) {
		t.Fatal(o, err)
	}
	for _, s := range []string{"placed", "placed:DESC", "placed:up", ":asc", "placed:asc:x"} {
		if _, err := ParseOrder(s); CodeOf(err) != CodeQueryInvalid && s != ":asc" && s != "placed:asc:x" {
			t.Errorf("%s: %v", s, err)
		}
	}
	// ":asc" and "placed:asc:x" parse but name no manifest column.
	for _, s := range []string{":asc", "placed:asc:x"} {
		o, err := ParseOrder(s)
		if err == nil {
			_, err = BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id"}, OrderBy: []Order{o}})
		}
		if CodeOf(err) == "" {
			t.Errorf("%s accepted", s)
		}
	}
	if m, err := ParseMeasure("count:*"); err != nil || m.Label() != "count:*" {
		t.Fatal(m, err)
	}
	for _, s := range []string{"sum:*", "count", "median:amount", "Sum:amount"} {
		if _, err := ParseMeasure(s); CodeOf(err) != CodeQueryInvalid {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestEncoder(t *testing.T) {
	st, err := BuildRows(shop(), Rows{Table: "shop.customers", Columns: []string{"id", "name", "ssn", "tier"}, Limit: 2, Access: Access{Classes: []Class{ClassPublic}}})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEncoder(st, 1<<20)
	for i, row := range [][]*string{{ptr("1"), ptr("gold")}, {ptr("2"), nil}, {ptr("3"), ptr("x")}} {
		more, err := e.Add(row)
		if err != nil {
			t.Fatal(err)
		}
		if more != (i < 2) {
			t.Fatalf("row %d: more %v", i, more)
		}
	}
	want := `{"columns":["id","name","ssn","tier"],"rows":[[1,"[redacted:pii]","[redacted:secret]","gold"],[2,"[redacted:pii]","[redacted:secret]",null]],"truncated":true,"redacted":4}`
	if got := string(e.Bytes()); got != want {
		t.Fatalf("answer\n got %s\nwant %s", got, want)
	}
	if e.Rows() != 2 || e.Redactions() != 4 || !e.Truncated() {
		t.Fatalf("counts %d %d %v", e.Rows(), e.Redactions(), e.Truncated())
	}
	if !json.Valid(e.Bytes()) {
		t.Fatal("invalid JSON")
	}
	// Exactly the limit is not truncated.
	e = NewEncoder(st, 1<<20)
	if _, err := e.Add([]*string{ptr("1"), ptr("a")}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Add([]*string{ptr("2"), ptr("b")}); err != nil {
		t.Fatal(err)
	}
	if e.Truncated() {
		t.Fatal("truncated at the limit")
	}
	if _, err := e.Add([]*string{ptr("1")}); err == nil && !e.Truncated() {
		t.Fatal("short row accepted")
	}
}

func TestEncoder_Types(t *testing.T) {
	st, err := BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"id", "amount", "paid", "placed", "status"}})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEncoder(st, 1<<20)
	if _, err := e.Add([]*string{ptr("42"), ptr("10.50"), ptr("t"), ptr("2026-10-17 10:00:00+00"), ptr(`a"b</script>`)}); err != nil {
		t.Fatal(err)
	}
	want := `{"columns":["id","amount","paid","placed","status"],"rows":[[42,"10.50",true,"2026-10-17 10:00:00+00","a\"b</script>"]],"truncated":false,"redacted":0}`
	if got := string(e.Bytes()); got != want {
		t.Fatalf("answer\n got %s\nwant %s", got, want)
	}
	for _, row := range [][]*string{
		{ptr("4 2"), nil, nil, nil, nil},
		{ptr("1"), nil, ptr("maybe"), nil, nil},
	} {
		if _, err := NewEncoder(st, 1<<20).Add(row); err == nil {
			t.Errorf("row %v accepted", row)
		}
	}
}

func TestEncoder_ByteLimit(t *testing.T) {
	st, err := BuildRows(shop(), Rows{Table: "shop.orders", Columns: []string{"status"}})
	if err != nil {
		t.Fatal(err)
	}
	const limit = 400
	e := NewEncoder(st, limit)
	big := strings.Repeat("x", 100)
	n := 0
	for {
		more, err := e.Add([]*string{&big})
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
		n++
	}
	if !e.Truncated() || n == 0 || len(e.Bytes()) > limit {
		t.Fatalf("rows %d, %d bytes, truncated %v", n, len(e.Bytes()), e.Truncated())
	}
}

func TestDescribe(t *testing.T) {
	out, err := Describe(shop(), Access{Classes: []Class{ClassPublic, ClassInternal}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, hidden := range []string{"ssn", "email", `"name":"name"`} {
		if strings.Contains(s, hidden) {
			t.Errorf("%s described: %s", hidden, s)
		}
	}
	if !strings.Contains(s, `{"table":"shop.orders","max_rows":50,`) || !strings.Contains(s, `"subject"`) {
		t.Errorf("describe %s", s)
	}
	out, _ = Describe(shop(), Access{})
	if strings.Contains(string(out), "ssn") || !strings.Contains(string(out), "email") {
		t.Errorf("describe without obligation %s", out)
	}
}

func TestLocalSettings(t *testing.T) {
	m := shop()
	m.StatementTimeoutMS = 1500
	got, err := LocalSettings(m)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"SET LOCAL statement_timeout = 1500",
		"SET LOCAL lock_timeout = 1000",
		"SET LOCAL idle_in_transaction_session_timeout = 1500",
		"SET LOCAL search_path = pg_catalog",
		"SET LOCAL TimeZone = 'UTC'",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("settings %q", got)
	}
	if p := StartupParams(); p["default_transaction_read_only"] != "on" || p["application_name"] != ApplicationName {
		t.Fatalf("startup %v", p)
	}
	m.StatementTimeoutMS = MaxStatementTimeout + 1
	_, err = LocalSettings(m)
	code(t, err, CodeManifestInvalid)
}

// FuzzBuildRows: whatever the agent sends, the SQL text holds only fixed
// tokens and manifest identifiers, and every value is a parameter.
func FuzzBuildRows(f *testing.F) {
	f.Add("status", "eq", "paid", "placed", true)
	f.Add(`id"; DROP`, "prefix", `'%_\`, "ssn", false)
	f.Add("customer_id", "in", "1", "id", false)
	f.Fuzz(func(t *testing.T, col, op, val, order string, desc bool) {
		st, err := BuildRows(shop(), Rows{
			Table:   "shop.orders",
			Columns: []string{col},
			Filters: []Filter{{Column: col, Op: Op(op), Value: &val}, {Column: col, Op: OpIn, Values: []string{val}}},
			OrderBy: []Order{{Column: order, Desc: desc}},
			Scope:   &RecordScope{Key: "customer", Values: []string{"1"}},
		})
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatalf("uncoded error %v", err)
			}
			return
		}
		assertOnlyKnownTokens(t, st.SQL)
	})
}
