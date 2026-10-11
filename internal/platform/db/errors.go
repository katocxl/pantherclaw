// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"errors"

	"github.com/jackc/pgx/v5"
)

// IsNoRows reports whether err means a query matched no row. Under forced
// RLS this is also what another org's id looks like, so callers map it to
// NotFound and never to a more specific error.
func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// IsForeignKeyViolation reports a foreign-key violation (SQLSTATE 23503),
// for example a reference to an id of another org.
func IsForeignKeyViolation(err error) bool { return hasCode(err, "23503") }

// IsCheckViolation reports a check violation (SQLSTATE 23514), a trigger's
// refusal included.
func IsCheckViolation(err error) bool { return hasCode(err, "23514") }
