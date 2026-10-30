// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgfanout is the Postgres adapter of the fan-out port:
// pg_notify in the publisher's transaction, and one LISTEN connection per
// subscription, reconnecting with backoff (G0 M18 S18e, D157; G10: shared
// state in Postgres only).
package pgfanout

import (
	"context"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/fanout"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Bus publishes and subscribes through one pool.
type Bus struct {
	pool *db.Pool
	log  *slog.Logger
}

var (
	_ fanout.Publisher  = (*Bus)(nil)
	_ fanout.Subscriber = (*Bus)(nil)
)

// New returns a Bus over pool.
func New(pool *db.Pool, log *slog.Logger) *Bus {
	if log == nil {
		log = pclog.Discard()
	}
	return &Bus{pool: pool, log: log}
}

// Publish implements fanout.Publisher with pg_notify, delivered at commit.
func (b *Bus) Publish(ctx context.Context, tx fanout.Execer, channel, payload string) error {
	if err := fanout.Validate(channel, payload); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)", channel, payload)
	return err
}

// Subscribe implements fanout.Subscriber. It returns nil when ctx ends.
func (b *Bus) Subscribe(ctx context.Context, channel string, handle func(payload string)) error {
	if err := fanout.Validate(channel, ""); err != nil {
		return err
	}
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		err := b.listen(ctx, channel, handle)
		if ctx.Err() != nil {
			return nil //nolint:nilerr // shutdown, not a failure
		}
		b.log.WarnContext(ctx, "fanout.listen_failed", slog.String("channel", channel), pclog.Err(err))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Second)
	}
	return nil
}

func (b *Bus) listen(ctx context.Context, channel string, handle func(string)) error {
	conn, err := b.pool.Pgx().Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "UNLISTEN *")
		conn.Release()
	}()
	// The channel name is validated (fanout.Validate), so it is a safe
	// identifier; LISTEN takes no parameters.
	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		handle(n.Payload)
	}
}
