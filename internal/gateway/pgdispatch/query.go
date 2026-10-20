// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgdispatch

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Op is a filter operator (the query_filter param type, D9).
type Op string

// Operators.
const (
	OpEq      Op = "eq"
	OpNe      Op = "ne"
	OpLt      Op = "lt"
	OpLe      Op = "le"
	OpGt      Op = "gt"
	OpGe      Op = "ge"
	OpIn      Op = "in"
	OpIsNull  Op = "is_null"
	OpNotNull Op = "not_null"
	OpPrefix  Op = "prefix"
)

var comparison = map[Op]string{OpEq: "=", OpNe: "<>", OpLt: "<", OpLe: "<=", OpGt: ">", OpGe: ">="}

// Query limits (D9).
const (
	MaxFilters     = 20
	MaxValueLength = 256
	MaxInValues    = 100
	MaxScopeValues = 100
)

// Filter is one predicate. Value is set for the comparisons and prefix,
// Values for in, neither for is_null and not_null.
type Filter struct {
	Column string   `json:"column"`
	Op     Op       `json:"op"`
	Value  *string  `json:"value,omitzero"`
	Values []string `json:"values,omitzero"`
}

// ParseFilters decodes a query_filter value: a JSON list of predicates. A
// scalar may be a JSON string, number or boolean; it is kept as its text.
// Anything else, an unknown field or trailing data is refused.
func ParseFilters(raw []byte) ([]Filter, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var items []struct {
		Column string           `json:"column"`
		Op     Op               `json:"op"`
		Value  jsontext.Value   `json:"value"`
		Values []jsontext.Value `json:"values"`
	}
	// Duplicate members, unknown members and trailing data are refused.
	if err := json.Unmarshal(raw, &items, json.RejectUnknownMembers(true)); err != nil {
		return nil, queryErr("filters are not a list of predicates: %v", err)
	}
	if len(items) > MaxFilters {
		return nil, queryErr("at most %d filters", MaxFilters)
	}
	out := make([]Filter, 0, len(items))
	for _, it := range items {
		f := Filter{Column: it.Column, Op: it.Op}
		if it.Value != nil {
			v, err := scalar(it.Value)
			if err != nil {
				return nil, err
			}
			f.Value = &v
		}
		if it.Values != nil {
			f.Values = make([]string, 0, len(it.Values))
			for _, r := range it.Values {
				v, err := scalar(r)
				if err != nil {
					return nil, err
				}
				f.Values = append(f.Values, v)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

func scalar(raw jsontext.Value) (string, error) {
	switch raw.Kind() {
	case jsontext.KindString:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", queryErr("a filter value is not a string: %v", err)
		}
		return s, nil
	case jsontext.KindTrue, jsontext.KindFalse, jsontext.KindNumber:
		return string(bytes.TrimSpace(raw)), nil
	case jsontext.KindInvalid, jsontext.KindNull, jsontext.KindBeginObject, jsontext.KindEndObject, jsontext.KindBeginArray, jsontext.KindEndArray:
		return "", queryErr("a filter value must be a string, number or boolean")
	}
	return "", queryErr("a filter value must be a string, number or boolean")
}

// Order is one sort key.
type Order struct {
	Column string
	Desc   bool
}

// ParseOrder parses an order_by item, col:asc or col:desc.
func ParseOrder(s string) (Order, error) {
	col, dir, ok := strings.Cut(s, ":")
	if !ok || (dir != "asc" && dir != "desc") {
		return Order{}, queryErr("order_by %q is not column:asc or column:desc", s)
	}
	return Order{Column: col, Desc: dir == "desc"}, nil
}

// Measure is one aggregate: count, sum, avg, min or max over a column, or
// count over "*".
type Measure struct {
	Func   string
	Column string
}

// Label is the measure's answer column name, func:column.
func (m Measure) Label() string { return m.Func + ":" + m.Column }

var measureFuncs = []string{"count", "sum", "avg", "min", "max"}

// ParseMeasure parses a measures item, func:column or count:*.
func ParseMeasure(s string) (Measure, error) {
	fn, col, ok := strings.Cut(s, ":")
	if !ok || !slices.Contains(measureFuncs, fn) || (col == "*" && fn != "count") {
		return Measure{}, queryErr("measure %q is not func:column (count, sum, avg, min, max) or count:*", s)
	}
	return Measure{Func: fn, Column: col}, nil
}

// Access is what the agent may read, from the grant and the decision's
// obligations: Tables is the decision's table bound as schema.table ids
// (nil: every manifest table), Columns its column bound (nil: every
// manifest column), Classes the classes a data_classes obligation allows
// (nil: no obligation, every class but secret). Secret is never readable.
type Access struct {
	Tables  []string
	Columns []string
	Classes []Class
}

func (a Access) table(ref string) bool {
	return a.Tables == nil || slices.Contains(a.Tables, ref)
}

// Readable reports whether a column's values may reach the agent.
func (a Access) Readable(c Column) bool {
	if c.Class == ClassSecret {
		return false
	}
	return a.Classes == nil || slices.Contains(a.Classes, c.Class)
}

func (a Access) bounded(name string) bool {
	return a.Columns == nil || slices.Contains(a.Columns, name)
}

// RecordScope is a record_scope obligation: only records whose scope
// column is one of Values (D20).
type RecordScope struct {
	Key    string
	Values []string
}

// Rows is a postgres.rows.read query.
type Rows struct {
	Table   string // target id, schema.table
	Columns []string
	Filters []Filter
	OrderBy []Order
	// Limit is the agent's requested row limit (0: none); Clamp the
	// decision's count_max clamp (0: none).
	Limit  int
	Clamp  int
	Access Access
	Scope  *RecordScope
}

// Aggregate is a postgres.rows.aggregate query.
type Aggregate struct {
	Table    string
	GroupBy  []string
	Measures []Measure
	Filters  []Filter
	Limit    int // groups
	Clamp    int
	Access   Access
	Scope    *RecordScope
}

// Output is one answer column: either the next selected SQL column, read
// as text and encoded as Type, or a value withheld because of its class.
type Output struct {
	Name     string
	Type     ColumnType
	Redacted Class // "" when the value is selected
}

// MaxValueChars is the most characters of one returned value (D72): every
// selected value is cut in SQL to one character more, so one row never
// holds more than that in memory, and the encoder cuts it to this length
// and flags the answer's truncated_values.
const MaxValueChars = 4096

// Statement is one built query. Every value is in Args; SQL holds only
// manifest identifiers, fixed keywords and $n placeholders. Every selected
// column is cast to text and cut to MaxValueChars+1 characters, so a row
// scans into []*string. Limit is the row count the answer may carry; the
// SQL asks for one more to report truncation.
type Statement struct {
	SQL    string
	Args   []any
	Output []Output
	Limit  int
}

// Selected is the number of SQL columns a row of the statement has.
func (s *Statement) Selected() int {
	n := 0
	for _, o := range s.Output {
		if o.Redacted == "" {
			n++
		}
	}
	return n
}

type builder struct {
	m     *Manifest
	t     *Table
	acc   Access
	args  []any
	where []string
}

func newBuilder(m Manifest, ref string, acc Access) (*builder, error) {
	n, err := m.Normalized()
	if err != nil {
		return nil, err
	}
	t, err := n.Table(ref)
	if err != nil {
		return nil, err
	}
	if !acc.table(t.Ref()) {
		return nil, &Error{Code: CodeTableNotAllowed, Detail: fmt.Sprintf("table %s is outside the decision's tables", t.Ref())}
	}
	for _, c := range acc.Classes {
		if !slices.Contains(classes, c) {
			return nil, queryErr("unknown class %q", c)
		}
	}
	return &builder{m: &n, t: t, acc: acc}, nil
}

// col is a column qualified by its table, so ORDER BY and GROUP BY bind
// to the typed source column and never to a ::text output column of the
// same name (D72).
func (b *builder) col(c Column) string { return quote(b.t.Schema, b.t.Name, c.Name) }

// selected is a value expression as the statement returns it.
func selected(expr string) string {
	return "left(" + expr + "::text, " + strconv.Itoa(MaxValueChars+1) + ")"
}

func (b *builder) arg(v any) string {
	b.args = append(b.args, v)
	return "$" + strconv.Itoa(len(b.args))
}

// column returns a manifest column the query may name.
func (b *builder) column(name string) (Column, error) {
	c, ok := b.t.Column(name)
	if !ok || !b.acc.bounded(name) {
		return Column{}, &Error{Code: CodeColumnNotAllowed, Detail: fmt.Sprintf("column %q may not be read on %s", name, b.t.Ref())}
	}
	return c, nil
}

// readable returns a column whose values the query uses: filters, sort
// and group keys and measures may only name columns whose class may be
// read, or they would reveal withheld values (D16).
func (b *builder) readable(name, use string) (Column, error) {
	c, err := b.column(name)
	if err != nil {
		return Column{}, err
	}
	if !b.acc.Readable(c) {
		return Column{}, &Error{Code: CodeColumnNotAllowed, Detail: fmt.Sprintf("column %q (%s) may not be used to %s", name, c.Class, use)}
	}
	return c, nil
}

func (b *builder) filters(fs []Filter) error {
	if len(fs) > MaxFilters {
		return queryErr("at most %d filters", MaxFilters)
	}
	for _, f := range fs {
		c, err := b.readable(f.Column, "filter")
		if err != nil {
			return err
		}
		col, typ := b.col(c), sqlType[c.Type]
		hasValue, hasValues := f.Value != nil, f.Values != nil
		switch f.Op {
		case OpEq, OpNe, OpLt, OpLe, OpGt, OpGe:
			if !hasValue || hasValues {
				return queryErr("%s on %s takes one value", f.Op, c.Name)
			}
			if err := checkValue(c, *f.Value); err != nil {
				return err
			}
			b.where = append(b.where, fmt.Sprintf("%s %s %s::text::%s", col, comparison[f.Op], b.arg(*f.Value), typ))
		case OpIn:
			if hasValue || len(f.Values) == 0 || len(f.Values) > MaxInValues {
				return queryErr("in on %s takes 1..%d values", c.Name, MaxInValues)
			}
			for _, v := range f.Values {
				if err := checkValue(c, v); err != nil {
					return err
				}
			}
			b.where = append(b.where, fmt.Sprintf("%s = ANY(%s::text[]::%s[])", col, b.arg(slices.Clone(f.Values)), typ))
		case OpIsNull, OpNotNull:
			if hasValue || hasValues {
				return queryErr("%s on %s takes no value", f.Op, c.Name)
			}
			b.where = append(b.where, col+map[Op]string{OpIsNull: " IS NULL", OpNotNull: " IS NOT NULL"}[f.Op])
		case OpPrefix:
			if !hasValue || hasValues {
				return queryErr("prefix on %s takes one value", c.Name)
			}
			if c.Type != TypeText {
				return queryErr("prefix applies to text columns only, not %s (%s)", c.Name, c.Type)
			}
			if err := checkValue(c, *f.Value); err != nil {
				return err
			}
			b.where = append(b.where, fmt.Sprintf(`%s LIKE %s::text ESCAPE E'\\'`, col, b.arg(LikePrefix(*f.Value))))
		default:
			return queryErr("unknown filter operator %q", f.Op)
		}
	}
	return nil
}

// scope adds the mandatory record_scope predicate (D20). It does not ask
// whether the agent may read the scope column: the predicate is the
// Authority's, not the agent's.
func (b *builder) scope(s *RecordScope) error {
	if s == nil {
		return nil
	}
	if b.t.ScopeKey == "" || b.t.ScopeKey != s.Key {
		return &Error{Code: CodeScopeUnsupported, Detail: fmt.Sprintf("table %s cannot be scoped by %q", b.t.Ref(), s.Key)}
	}
	if len(s.Values) > MaxScopeValues {
		return &Error{Code: CodeScopeUnsupported, Detail: fmt.Sprintf("a record scope holds at most %d values", MaxScopeValues)}
	}
	c, _ := b.t.Column(b.t.ScopeColumn) // validated
	for _, v := range s.Values {
		if err := checkValue(c, v); err != nil {
			return &Error{Code: CodeScopeUnsupported, Detail: "record scope: " + err.Error()}
		}
	}
	b.where = append(b.where, fmt.Sprintf("%s = ANY(%s::text[]::%s[])", b.col(c), b.arg(append([]string{}, s.Values...)), sqlType[c.Type]))
	return nil
}

func (b *builder) whereSQL() string {
	if len(b.where) == 0 {
		return ""
	}
	parts := make([]string, len(b.where))
	for i, w := range b.where {
		parts[i] = "(" + w + ")"
	}
	return " WHERE " + strings.Join(parts, " AND ")
}

// limit is the smallest of the connection's, the table's, the clamp's and
// the request's row limits.
func (b *builder) limit(request, clamp int) (int, error) {
	if request < 0 || clamp < 0 {
		return 0, queryErr("a limit must not be negative")
	}
	n := b.m.MaxRows
	for _, l := range []int{b.t.MaxRows, clamp, request} {
		if l > 0 {
			n = min(n, l)
		}
	}
	return n, nil
}

func (b *builder) from() string { return " FROM " + quote(b.t.Schema, b.t.Name) }

// BuildRows builds the statement of a postgres.rows.read query. A selected
// column whose class may not be read is not selected at all; the answer
// carries a placeholder in its place.
func BuildRows(m Manifest, q Rows) (*Statement, error) {
	b, err := newBuilder(m, q.Table, q.Access)
	if err != nil {
		return nil, err
	}
	if len(q.Columns) == 0 {
		return nil, queryErr("name at least one column")
	}
	st := &Statement{}
	var sel []string
	for i, name := range q.Columns {
		if slices.Contains(q.Columns[:i], name) {
			return nil, queryErr("column %s is named twice", name)
		}
		c, err := b.column(name)
		if err != nil {
			return nil, err
		}
		o := Output{Name: c.Name, Type: c.Type}
		if b.acc.Readable(c) {
			sel = append(sel, selected(b.col(c)))
		} else {
			o.Redacted = c.Class
		}
		st.Output = append(st.Output, o)
	}
	if err := b.filters(q.Filters); err != nil {
		return nil, err
	}
	if err := b.scope(q.Scope); err != nil {
		return nil, err
	}
	var order []string
	for i, o := range q.OrderBy {
		if slices.ContainsFunc(q.OrderBy[:i], func(p Order) bool { return p.Column == o.Column }) {
			return nil, queryErr("column %s is sorted twice", o.Column)
		}
		c, err := b.readable(o.Column, "sort")
		if err != nil {
			return nil, err
		}
		order = append(order, b.col(c)+map[bool]string{false: " ASC", true: " DESC"}[o.Desc])
	}
	if st.Limit, err = b.limit(q.Limit, q.Clamp); err != nil {
		return nil, err
	}
	var sql strings.Builder
	sql.WriteString("SELECT " + strings.Join(sel, ", ") + b.from() + b.whereSQL())
	if len(order) > 0 {
		sql.WriteString(" ORDER BY " + strings.Join(order, ", "))
	}
	sql.WriteString(" LIMIT " + strconv.Itoa(st.Limit+1))
	st.SQL, st.Args = sql.String(), b.args
	return st, nil
}

// BuildAggregate builds the statement of a postgres.rows.aggregate query.
// Groups with fewer than the manifest's min_group_size rows are never
// returned (HR-312): the HAVING clause drops them in the database.
func BuildAggregate(m Manifest, q Aggregate) (*Statement, error) {
	b, err := newBuilder(m, q.Table, q.Access)
	if err != nil {
		return nil, err
	}
	if len(q.Measures) == 0 {
		return nil, queryErr("name at least one measure")
	}
	st := &Statement{}
	var sel, group []string
	for i, name := range q.GroupBy {
		if slices.Contains(q.GroupBy[:i], name) {
			return nil, queryErr("column %s is grouped twice", name)
		}
		c, err := b.readable(name, "group")
		if err != nil {
			return nil, err
		}
		group = append(group, b.col(c))
		sel = append(sel, selected(b.col(c)))
		st.Output = append(st.Output, Output{Name: c.Name, Type: c.Type})
	}
	for i, ms := range q.Measures {
		if slices.Contains(q.Measures[:i], ms) {
			return nil, queryErr("measure %s is named twice", ms.Label())
		}
		expr, typ, err := b.measure(ms)
		if err != nil {
			return nil, err
		}
		sel = append(sel, selected(expr))
		st.Output = append(st.Output, Output{Name: ms.Label(), Type: typ})
	}
	if err := b.filters(q.Filters); err != nil {
		return nil, err
	}
	if err := b.scope(q.Scope); err != nil {
		return nil, err
	}
	if st.Limit, err = b.limit(q.Limit, q.Clamp); err != nil {
		return nil, err
	}
	var sql strings.Builder
	sql.WriteString("SELECT " + strings.Join(sel, ", ") + b.from() + b.whereSQL())
	if len(group) > 0 {
		sql.WriteString(" GROUP BY " + strings.Join(group, ", "))
	}
	sql.WriteString(" HAVING count(*) >= " + strconv.Itoa(b.m.MinGroupSize))
	if len(group) > 0 {
		sql.WriteString(" ORDER BY " + strings.Join(group, ", "))
	}
	sql.WriteString(" LIMIT " + strconv.Itoa(st.Limit+1))
	st.SQL, st.Args = sql.String(), b.args
	return st, nil
}

var (
	numericTypes = []ColumnType{TypeInt, TypeBigint, TypeNumeric}
	boundTypes   = []ColumnType{TypeInt, TypeBigint, TypeNumeric, TypeDate, TypeTimestamptz}
)

func (b *builder) measure(ms Measure) (expr string, typ ColumnType, err error) {
	if !slices.Contains(measureFuncs, ms.Func) {
		return "", "", queryErr("unknown measure %q", ms.Func)
	}
	if ms.Column == "*" {
		if ms.Func != "count" {
			return "", "", queryErr("only count takes *")
		}
		return "count(*)", TypeBigint, nil
	}
	if ms.Func == "count" {
		// A count returns a number, never a value: any column but a secret
		// one, whatever the classes allow (D79).
		c, err := b.column(ms.Column)
		if err != nil {
			return "", "", err
		}
		if c.Class == ClassSecret {
			return "", "", &Error{Code: CodeColumnNotAllowed, Detail: fmt.Sprintf("column %q is secret", c.Name)}
		}
		return "count(" + b.col(c) + ")", TypeBigint, nil
	}
	c, err := b.readable(ms.Column, "measure")
	if err != nil {
		return "", "", err
	}
	col := b.col(c)
	// sum, avg, min and max carry values of the column; min and max return
	// one row's value outright. They apply only to public or internal
	// columns (D72, HR-312).
	if c.Class != ClassPublic && c.Class != ClassInternal {
		return "", "", &Error{Code: CodeColumnNotAllowed, Detail: fmt.Sprintf("%s does not apply to %s columns such as %s", ms.Func, c.Class, c.Name)}
	}
	switch ms.Func {
	case "sum", "avg":
		if !slices.Contains(numericTypes, c.Type) {
			return "", "", queryErr("%s applies to numeric columns only, not %s (%s)", ms.Func, c.Name, c.Type)
		}
		if ms.Func == "sum" && c.Type == TypeInt {
			return "sum(" + col + ")", TypeBigint, nil
		}
		return ms.Func + "(" + col + ")", TypeNumeric, nil
	default: // min, max
		if !slices.Contains(boundTypes, c.Type) {
			return "", "", queryErr("%s applies to numeric, date and timestamptz columns only, not %s (%s)", ms.Func, c.Name, c.Type)
		}
		return ms.Func + "(" + col + ")", c.Type, nil
	}
}

// LikePrefix is the LIKE pattern matching values that start with s, with
// the escape character backslash (D16).
func LikePrefix(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s) + "%"
}

var (
	intRe     = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,18})$`)
	numericRe = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,30})(\.[0-9]{1,30})?$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// checkValue refuses a value that is not of the column's type in its one
// canonical spelling, so the database's cast cannot fail or reinterpret
// it.
func checkValue(c Column, v string) error {
	bad := func() error { return queryErr("value for %s is not a %s", c.Name, c.Type) }
	if !utf8.ValidString(v) || strings.ContainsRune(v, 0) || utf8.RuneCountInString(v) > MaxValueLength {
		return queryErr("value for %s must be valid text of at most %d characters", c.Name, MaxValueLength)
	}
	switch c.Type {
	case TypeText:
		return nil
	case TypeInt, TypeBigint:
		bits := map[ColumnType]int{TypeInt: 32, TypeBigint: 64}[c.Type]
		if _, err := strconv.ParseInt(v, 10, bits); err != nil || !intRe.MatchString(v) {
			return bad()
		}
	case TypeNumeric:
		if !numericRe.MatchString(v) {
			return bad()
		}
	case TypeBool:
		if v != "true" && v != "false" {
			return bad()
		}
	case TypeDate:
		if t, err := time.Parse(time.DateOnly, v); err != nil || t.Format(time.DateOnly) != v || t.Year() < 1 {
			return bad()
		}
	case TypeTimestamptz:
		if t, err := time.Parse(time.RFC3339Nano, v); err != nil || t.Year() < 1 {
			return bad()
		}
	case TypeUUID:
		if !uuidRe.MatchString(v) {
			return bad()
		}
	default:
		return bad()
	}
	return nil
}

func queryErr(format string, args ...any) error {
	return &Error{Code: CodeQueryInvalid, Detail: fmt.Sprintf(format, args...)}
}
