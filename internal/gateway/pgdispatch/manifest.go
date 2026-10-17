// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgdispatch turns an authorized read of a postgres connection into
// one parameterised, read-only SQL statement and encodes its answer
// (PN-017.4, F759; G0 M14 D15–D17). It is pure: it neither dials nor
// queries. The statement is built only from the typed query the ActionIR
// carries (HR-307): every table and column is looked up in the connection's
// manifest by exact name and emitted as a quoted identifier, and every
// value is a $n parameter cast to the manifest's type. Nothing the agent
// sends is ever spliced into the SQL text.
package pgdispatch

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// ColumnType is a column's declared type. The list is closed: json, jsonb,
// bytea and arrays are not readable through the connector.
type ColumnType string

// Column types.
const (
	TypeText        ColumnType = "text"
	TypeInt         ColumnType = "int"
	TypeBigint      ColumnType = "bigint"
	TypeNumeric     ColumnType = "numeric"
	TypeBool        ColumnType = "bool"
	TypeDate        ColumnType = "date"
	TypeTimestamptz ColumnType = "timestamptz"
	TypeUUID        ColumnType = "uuid"
)

// sqlType is the type name each column type is cast to.
var sqlType = map[ColumnType]string{
	TypeText:        "text",
	TypeInt:         "integer",
	TypeBigint:      "bigint",
	TypeNumeric:     "numeric",
	TypeBool:        "boolean",
	TypeDate:        "date",
	TypeTimestamptz: "timestamptz",
	TypeUUID:        "uuid",
}

// Class is a column's data class (F101).
type Class string

// Classes. Secret is never returned to an agent.
const (
	ClassPublic   Class = "public"
	ClassInternal Class = "internal"
	ClassPII      Class = "pii"
	ClassSecret   Class = "secret"
)

var classes = []Class{ClassPublic, ClassInternal, ClassPII, ClassSecret}

// Column is one readable column of a manifest table.
type Column struct {
	Name  string     `json:"name"`
	Type  ColumnType `json:"type"`
	Class Class      `json:"class"`
}

// Table is one table an agent may read, with its columns. ScopeKey names
// the record_scope obligation key the table is filtered by, through
// ScopeColumn (D20).
type Table struct {
	Schema      string   `json:"schema"`
	Name        string   `json:"name"`
	ScopeKey    string   `json:"scope_key,omitzero"`
	ScopeColumn string   `json:"scope_column,omitzero"`
	MaxRows     int      `json:"max_rows,omitzero"`
	Columns     []Column `json:"columns"`
}

// Ref is the table's target id, schema.table.
func (t *Table) Ref() string { return t.Schema + "." + t.Name }

// Column returns the column with exactly this name.
func (t *Table) Column(name string) (Column, bool) {
	for _, c := range t.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return Column{}, false
}

// Manifest is the admin allow-list of a postgres connection and its limits
// (D15). The zero limits take the defaults.
type Manifest struct {
	Tables             []Table `json:"tables"`
	MaxRows            int     `json:"max_rows,omitzero"`
	StatementTimeoutMS int     `json:"statement_timeout_ms,omitzero"`
	MaxResultBytes     int     `json:"max_result_bytes,omitzero"`
	MinGroupSize       int     `json:"min_group_size,omitzero"`
}

// Limits (D15).
const (
	DefaultMaxRows          = 200
	MaxRowsLimit            = 1000
	DefaultStatementTimeout = 5000
	MaxStatementTimeout     = 30000
	DefaultMaxResultBytes   = 1 << 20
	MaxResultBytesLimit     = 4 << 20
	MinResultBytes          = 1024
	DefaultMinGroupSize     = 5
	MinGroupSizeFloor       = 2
	// LockTimeoutMS is the lock wait of every statement (D16).
	LockTimeoutMS = 1000
)

// identRe is the only identifier spelling the connector accepts: no quoted
// identifiers, no upper case (D15).
var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// ValidIdentifier reports whether s is an identifier the connector accepts.
func ValidIdentifier(s string) bool { return identRe.MatchString(s) }

// quote emits identifiers the manifest already holds, dot-joined (HR-307).
// They match identRe, so quoting needs no escaping; a quote character is
// doubled all the same, as pgx.Identifier.Sanitize does.
func quote(parts ...string) string {
	q := make([]string, len(parts))
	for i, p := range parts {
		q[i] = `"` + strings.ReplaceAll(p, `"`, `""`) + `"`
	}
	return strings.Join(q, ".")
}

// Normalized returns the manifest with its defaults filled in, or an error
// with code MANIFEST_INVALID.
func (m Manifest) Normalized() (Manifest, error) {
	def := func(v, d int) int {
		if v == 0 {
			return d
		}
		return v
	}
	n := m
	n.MaxRows = def(m.MaxRows, DefaultMaxRows)
	n.StatementTimeoutMS = def(m.StatementTimeoutMS, DefaultStatementTimeout)
	n.MaxResultBytes = def(m.MaxResultBytes, DefaultMaxResultBytes)
	n.MinGroupSize = def(m.MinGroupSize, DefaultMinGroupSize)
	return n, n.validate()
}

func (m Manifest) validate() error {
	switch {
	case m.MaxRows < 1 || m.MaxRows > MaxRowsLimit:
		return manifestErr("max_rows must be 1..%d", MaxRowsLimit)
	case m.StatementTimeoutMS < 1 || m.StatementTimeoutMS > MaxStatementTimeout:
		return manifestErr("statement_timeout_ms must be 1..%d", MaxStatementTimeout)
	case m.MaxResultBytes < MinResultBytes || m.MaxResultBytes > MaxResultBytesLimit:
		return manifestErr("max_result_bytes must be %d..%d", MinResultBytes, MaxResultBytesLimit)
	case m.MinGroupSize < MinGroupSizeFloor:
		return manifestErr("min_group_size must be at least %d", MinGroupSizeFloor)
	case len(m.Tables) == 0:
		return manifestErr("the manifest lists no tables")
	}
	seen := map[string]bool{}
	for i := range m.Tables {
		t := &m.Tables[i]
		if err := t.validate(); err != nil {
			return err
		}
		if seen[t.Ref()] {
			return manifestErr("table %s is listed twice", t.Ref())
		}
		seen[t.Ref()] = true
	}
	return nil
}

func (t *Table) validate() error {
	if !ValidIdentifier(t.Schema) || !ValidIdentifier(t.Name) {
		return manifestErr("table %q.%q: schema and name must match %s", t.Schema, t.Name, identRe)
	}
	ref := t.Ref()
	// The system catalogs are never targets: pg_stat_activity, for one,
	// shows other sessions' queries to any role.
	if t.Schema == "information_schema" || strings.HasPrefix(t.Schema, "pg_") {
		return manifestErr("table %s: system schemas cannot be listed", ref)
	}
	switch {
	case t.MaxRows < 0 || t.MaxRows > MaxRowsLimit:
		return manifestErr("table %s: max_rows must be 0..%d", ref, MaxRowsLimit)
	case (t.ScopeKey == "") != (t.ScopeColumn == ""):
		return manifestErr("table %s: scope_key and scope_column go together", ref)
	case t.ScopeKey != "" && !ValidIdentifier(t.ScopeKey):
		return manifestErr("table %s: scope_key must match %s", ref, identRe)
	case len(t.Columns) == 0:
		return manifestErr("table %s lists no columns", ref)
	}
	seen := map[string]bool{}
	for _, c := range t.Columns {
		switch {
		case !ValidIdentifier(c.Name):
			return manifestErr("table %s: column %q must match %s", ref, c.Name, identRe)
		case sqlType[c.Type] == "":
			return manifestErr("table %s: column %s has unsupported type %q", ref, c.Name, c.Type)
		case !slices.Contains(classes, c.Class):
			return manifestErr("table %s: column %s has unknown class %q", ref, c.Name, c.Class)
		case seen[c.Name]:
			return manifestErr("table %s: column %s is listed twice", ref, c.Name)
		}
		seen[c.Name] = true
	}
	if t.ScopeColumn != "" && !seen[t.ScopeColumn] {
		return manifestErr("table %s: scope_column %s is not a listed column", ref, t.ScopeColumn)
	}
	return nil
}

// Table returns the manifest table a target id (schema.table) names, by
// exact match.
func (m *Manifest) Table(ref string) (*Table, error) {
	schema, name, ok := strings.Cut(ref, ".")
	if !ok || !ValidIdentifier(schema) || !ValidIdentifier(name) {
		return nil, &Error{Code: CodeTableNotAllowed, Detail: "the target is not a schema.table id"}
	}
	for i := range m.Tables {
		if t := &m.Tables[i]; t.Schema == schema && t.Name == name {
			return t, nil
		}
	}
	return nil, &Error{Code: CodeTableNotAllowed, Detail: fmt.Sprintf("table %s is not in the connection's manifest", ref)}
}

func manifestErr(format string, args ...any) error {
	return &Error{Code: CodeManifestInvalid, Detail: fmt.Sprintf(format, args...)}
}
