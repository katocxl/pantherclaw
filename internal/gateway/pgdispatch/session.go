// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgdispatch

import "strconv"

// The transaction every query runs in (HR-308): read only, at repeatable
// read, with local timeouts, and always rolled back.
const (
	BeginSQL    = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"
	RollbackSQL = "ROLLBACK"
	// ApplicationName is the pool's application_name.
	ApplicationName = "pantherclaw-gateway"
)

// StartupParams are the runtime parameters every pooled connection is
// opened with (D16): a session that is read only by default.
func StartupParams() map[string]string {
	return map[string]string{
		"application_name":              ApplicationName,
		"default_transaction_read_only": "on",
	}
}

// LocalSettings are the SET LOCAL statements that follow BeginSQL. The
// values are the manifest's validated integers, never agent input.
// search_path is pg_catalog alone, so the built-in casts and operators the
// statements use cannot be shadowed by objects in another schema, and
// TimeZone is UTC, so timestamps read the same from every connection.
func LocalSettings(m Manifest) ([]string, error) {
	n, err := m.Normalized()
	if err != nil {
		return nil, err
	}
	ms := strconv.Itoa(n.StatementTimeoutMS)
	return []string{
		"SET LOCAL statement_timeout = " + ms,
		"SET LOCAL lock_timeout = " + strconv.Itoa(LockTimeoutMS),
		"SET LOCAL idle_in_transaction_session_timeout = " + ms,
		"SET LOCAL search_path = pg_catalog",
		"SET LOCAL TimeZone = 'UTC'",
	}, nil
}
