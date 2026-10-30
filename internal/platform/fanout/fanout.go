// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package fanout is the port for waking every server instance when shared
// state changes (G0 M18 S18e, D157): a publisher announces a change on a
// named channel inside the transaction that made it, and each instance's
// subscriber wakes its local waiters. Payloads carry ids only, never
// customer data (HR-056); subscribers re-read the state they care about.
//
// The Postgres adapter (pgfanout) is LISTEN/NOTIFY, which is what the
// approvals waits, gateway watch and containment already use directly.
// Moving those callers onto the port is later work: this package changes
// no behaviour.
package fanout

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5/pgconn"
)

// MaxPayload bounds a payload (Postgres NOTIFY allows < 8000 bytes).
const MaxPayload = 1024

var channelName = regexp.MustCompile(`^pc_[a-z][a-z0-9_]{0,59}$`)

// ErrInvalid reports a bad channel name or payload.
var ErrInvalid = errors.New("fanout: invalid channel or payload")

// Validate checks a channel name and payload.
func Validate(channel, payload string) error {
	if !channelName.MatchString(channel) || len(payload) > MaxPayload {
		return ErrInvalid
	}
	return nil
}

// Execer runs a statement in the caller's transaction (db.TenantTx, pgx.Tx).
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Publisher announces a change. Delivery happens when the caller's
// transaction commits, and not at all if it rolls back.
type Publisher interface {
	Publish(ctx context.Context, tx Execer, channel, payload string) error
}

// Subscriber delivers every payload published on channel to handle until
// ctx ends. It reconnects after a failure; a waiter must still re-read on
// a timer, since a notification can be lost while reconnecting.
type Subscriber interface {
	Subscribe(ctx context.Context, channel string, handle func(payload string)) error
}
