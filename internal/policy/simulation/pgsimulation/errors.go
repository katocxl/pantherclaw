// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgsimulation

import (
	"context"
	"errors"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Infrastructure reports an error of the database, the network or the
// context: it fails a simulation step, which River retries. Any other
// replay error belongs to one recorded decision (a receipt that does not
// parse, say), which the runner counts as unevaluable (D34).
func Infrastructure(err error) bool {
	var pg *pgconn.PgError
	var conn *pgconn.ConnectError
	var ne net.Error
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, pgx.ErrTxClosed) ||
		errors.As(err, &pg) || errors.As(err, &conn) || errors.As(err, &ne) || pgconn.Timeout(err)
}
