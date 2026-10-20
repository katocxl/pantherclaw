// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgdispatch

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strconv"
)

// Redacted is the placeholder of a value withheld because of its class
// (D20).
func Redacted(c Class) string { return "[redacted:" + string(c) + "]" }

// Encoder builds the answer of a statement, {"columns":[…],"rows":[[…]],
// "truncated":bool,"truncated_values":bool,"redacted":n} (D16, D72), from
// rows scanned as text. It stops at the statement's row limit and before
// the answer would exceed the byte limit, and says so with truncated; a
// value longer than MaxValueChars is cut to that length, and
// truncated_values says so.
type Encoder struct {
	st        *Statement
	maxBytes  int
	head      []byte
	rows      bytes.Buffer
	n         int
	redacted  int
	truncated bool
	cut       bool
	full      bool
}

// tail is the most the closing bytes take:
// `],"truncated":false,"truncated_values":false,"redacted":`, a count and `}`.
const tail = 96

// NewEncoder returns an encoder for the statement's answer, at most
// maxBytes long.
func NewEncoder(st *Statement, maxBytes int) *Encoder {
	head := []byte(`{"columns":[`)
	for i, o := range st.Output {
		if i > 0 {
			head = append(head, ',')
		}
		head = append(head, '"') // names are identifiers or func:column
		head = append(head, o.Name...)
		head = append(head, '"')
	}
	return &Encoder{st: st, maxBytes: maxBytes, head: append(head, `],"rows":[`...)}
}

// Add adds one scanned row: one value per selected column, nil for NULL.
// It returns false once the encoder takes no more rows (the row limit or
// the byte limit is reached); the caller stops reading then.
func (e *Encoder) Add(row []*string) (bool, error) {
	if e.full {
		return false, nil
	}
	if e.n == e.st.Limit {
		e.truncated, e.full = true, true
		return false, nil
	}
	if len(row) != e.st.Selected() {
		return false, fmt.Errorf("pgdispatch: a row has %d values, the statement selects %d", len(row), e.st.Selected())
	}
	var b bytes.Buffer
	if e.n > 0 {
		b.WriteByte(',')
	}
	b.WriteByte('[')
	redacted, src, cut := 0, 0, false
	for i, o := range e.st.Output {
		if i > 0 {
			b.WriteByte(',')
		}
		if o.Redacted != "" {
			b.WriteString(`"` + Redacted(o.Redacted) + `"`)
			redacted++
			continue
		}
		v := row[src]
		if v != nil {
			if s, c := cutValue(*v); c {
				v, cut = &s, true
			}
		}
		if err := encodeValue(&b, o.Type, v); err != nil {
			return false, fmt.Errorf("pgdispatch: column %s: %w", o.Name, err)
		}
		src++
	}
	b.WriteByte(']')
	if len(e.head)+e.rows.Len()+b.Len()+tail > e.maxBytes {
		e.truncated, e.full = true, true
		return false, nil
	}
	e.rows.Write(b.Bytes())
	e.n++
	e.redacted += redacted
	e.cut = e.cut || cut
	return true, nil
}

// Rows is the number of rows the answer carries; Redactions the number of
// values it withheld (receipts record counts only, D20).
func (e *Encoder) Rows() int       { return e.n }
func (e *Encoder) Redactions() int { return e.redacted }
func (e *Encoder) Truncated() bool { return e.truncated }

// TruncatedValues reports whether a value was cut to MaxValueChars.
func (e *Encoder) TruncatedValues() bool { return e.cut }

// cutValue cuts a value to MaxValueChars characters.
func cutValue(s string) (string, bool) {
	if len(s) <= MaxValueChars {
		return s, false
	}
	n := 0
	for i := range s {
		if n == MaxValueChars {
			return s[:i], true
		}
		n++
	}
	return s, false
}

// Bytes returns the answer.
func (e *Encoder) Bytes() []byte {
	out := append(append([]byte{}, e.head...), e.rows.Bytes()...)
	out = append(out, `],"truncated":`...)
	out = strconv.AppendBool(out, e.truncated)
	out = append(out, `,"truncated_values":`...)
	out = strconv.AppendBool(out, e.cut)
	out = append(out, `,"redacted":`...)
	out = strconv.AppendInt(out, int64(e.redacted), 10)
	return append(out, '}')
}

// encodeValue writes a value Postgres returned as text: integers as JSON
// numbers, booleans as JSON booleans, everything else (numeric included,
// to keep its precision) as a JSON string.
func encodeValue(b *bytes.Buffer, t ColumnType, v *string) error {
	if v == nil {
		b.WriteString("null")
		return nil
	}
	switch t {
	case TypeInt, TypeBigint:
		if !intRe.MatchString(*v) {
			return fmt.Errorf("%q is not an integer", *v)
		}
		b.WriteString(*v)
	case TypeBool:
		switch *v {
		case "t", "true":
			b.WriteString("true")
		case "f", "false":
			b.WriteString("false")
		default:
			return fmt.Errorf("%q is not a boolean", *v)
		}
	case TypeText, TypeNumeric, TypeDate, TypeTimestamptz, TypeUUID:
		enc, err := jsontext.AppendQuote(nil, *v)
		if err != nil {
			return fmt.Errorf("the value is not valid UTF-8: %w", err)
		}
		b.Write(enc)
	default:
		return fmt.Errorf("unsupported type %q", t)
	}
	return nil
}

// DescribedColumn and DescribedTable are the postgres.tables.read answer.
type DescribedColumn struct {
	Name  string     `json:"name"`
	Type  ColumnType `json:"type"`
	Class Class      `json:"class"`
}

// DescribedTable is one table as the agent may see it.
type DescribedTable struct {
	Table   string            `json:"table"`
	MaxRows int               `json:"max_rows"`
	Columns []DescribedColumn `json:"columns"`
}

// Describe returns the manifest's tables within the agent's table bound and
// the columns it may read: columns outside its column bound, of a class it
// may not read, and every secret column are left out.
func Describe(m Manifest, acc Access) ([]byte, error) {
	n, err := m.Normalized()
	if err != nil {
		return nil, err
	}
	out := struct {
		Tables []DescribedTable `json:"tables"`
	}{Tables: []DescribedTable{}}
	for i := range n.Tables {
		t := &n.Tables[i]
		if !acc.table(t.Ref()) {
			continue
		}
		d := DescribedTable{Table: t.Ref(), MaxRows: n.MaxRows, Columns: []DescribedColumn{}}
		if t.MaxRows > 0 {
			d.MaxRows = min(d.MaxRows, t.MaxRows)
		}
		for _, c := range t.Columns {
			if acc.bounded(c.Name) && acc.Readable(c) {
				d.Columns = append(d.Columns, DescribedColumn(c))
			}
		}
		out.Tables = append(out.Tables, d)
	}
	return json.Marshal(out)
}
