// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgdispatch

import "errors"

// Codes of a refused query. Every refusal happens before any statement is
// sent.
const (
	// CodeManifestInvalid: the connection's manifest is not valid.
	CodeManifestInvalid = "MANIFEST_INVALID"
	// CodeTableNotAllowed: the target names no table of the manifest.
	CodeTableNotAllowed = "TABLE_NOT_ALLOWED"
	// CodeColumnNotAllowed: a column is not in the manifest table, is
	// outside the agent's columns, or is filtered, sorted, grouped or
	// measured although its class may not be read (D16).
	CodeColumnNotAllowed = "COLUMN_NOT_ALLOWED"
	// CodeScopeUnsupported: a record_scope obligation applies but the
	// table has no matching scope key (D20).
	CodeScopeUnsupported = "SCOPE_UNSUPPORTED"
	// CodeQueryInvalid: the query is malformed (an unknown operator, a
	// value that is not of the column's type, a bad limit).
	CodeQueryInvalid = "QUERY_INVALID"
)

// Error is a refusal with a code.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

// CodeOf returns the code of a refusal, or "" for another error.
func CodeOf(err error) string {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code
	}
	return ""
}
