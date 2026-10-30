// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Promotion detection (G0 M19 D202, D207, D213, D218, HR-496). A promotion
// moves the database to a new timeline. Behind a synchronous standby that
// applied every commit (synchronous_commit=remote_apply), nothing committed
// is lost; behind an asynchronous one, revocations, containment changes
// and budget reservations may be. pc.db_primary_timeline keeps the
// acknowledged timeline and whether sync was verified while it ran. A
// server that finds another timeline starts in the maintenance hold unless
// sync was verified at both ends: on the acknowledged timeline and on the
// new primary. `keys bump-epochs` acknowledges the new timeline once every
// epoch is raised.

// Replication is the replication the operator declares (db.replication).
type Replication string

// Declared replication.
const (
	// ReplicationAsync is the default: a promotion may lose commits.
	ReplicationAsync Replication = "async"
	// ReplicationSync declares one synchronous standby with
	// synchronous_commit=remote_apply. It counts only when the primary's
	// settings confirm it at start-up.
	ReplicationSync Replication = "sync"
)

// Valid reports a known replication.
func (r Replication) Valid() bool { return r == ReplicationAsync || r == ReplicationSync }

// Promotion is the result of the start-up check.
type Promotion struct {
	// Timeline is the primary's current timeline; Acknowledged the one
	// recorded before (0 on the first start, which records Timeline).
	Timeline, Acknowledged int64
	// Sync is the effective replication: declared sync and confirmed by
	// the primary's settings.
	Sync bool
	// Unverified is set when sync was declared but the primary's settings
	// do not confirm it; the replication then counts as async.
	Unverified bool
	// Hold is set when the timeline moved without sync verified at both
	// ends: the server must start in the maintenance hold.
	Hold bool
}

// ErrNoTimelineRow reports a database without the singleton row of
// pc.db_primary_timeline (migration 00230): the check cannot be made, so
// the server does not start.
var ErrNoTimelineRow = errors.New("db: pc.db_primary_timeline has no row; run `migrate up`")

// The failover queries (each one constant).
const (
	// primaryStateSQL reads the timeline WAL is written on now (it moves
	// the moment a standby is promoted, unlike the last checkpoint's) and
	// whether the primary runs verified sync: remote_apply with a
	// synchronous standby named.
	primaryStateSQL = `SELECT ('x' || substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8))::bit(32)::bigint,
		current_setting('synchronous_commit') = 'remote_apply' AND btrim(current_setting('synchronous_standby_names')) <> ''`
	acknowledgedSQL = `SELECT timeline, sync_verified FROM pc.db_primary_timeline FOR UPDATE`
	recordSQL       = `UPDATE pc.db_primary_timeline SET timeline = $1, sync_verified = $2, update_time = now()`
)

// CheckPromotion compares the primary's timeline with the acknowledged one
// for declared replication r, and arms the pool's watch for promotions
// while it runs (D213).
func (p *Pool) CheckPromotion(ctx context.Context, r Replication) (Promotion, error) {
	if !r.Valid() {
		return Promotion{}, fmt.Errorf("db: replication %q (use async or sync)", r)
	}
	var out Promotion
	err := p.InGlobalTx(ctx, GlobalFailover, func(ctx context.Context, tx GlobalTx) error {
		var tl int64
		var configured bool
		if err := tx.QueryRow(ctx, primaryStateSQL).Scan(&tl, &configured); err != nil {
			return err
		}
		var ack *int64
		var ackSync bool
		switch err := tx.QueryRow(ctx, acknowledgedSQL).Scan(&ack, &ackSync); {
		case IsNoRows(err):
			return ErrNoTimelineRow
		case err != nil:
			return err
		}
		var record bool
		out, record = decidePromotion(r, tl, ack, ackSync, configured)
		if record {
			return recordTimeline(ctx, tx, out.Timeline, out.Sync)
		}
		return nil
	})
	if err != nil {
		return Promotion{}, fmt.Errorf("db: check the primary timeline: %w", err)
	}
	if p.timeline != nil {
		p.timeline.arm(out)
	}
	return out, nil
}

// AcknowledgeTimeline records the primary's current timeline, after `keys
// bump-epochs` raised every organization's epoch, so the next start does
// not hold; sync counts as verified on it when r is sync and the primary
// confirms it. It returns the timeline.
func (p *Pool) AcknowledgeTimeline(ctx context.Context, r Replication) (int64, error) {
	var tl int64
	err := p.InGlobalTx(ctx, GlobalFailover, func(ctx context.Context, tx GlobalTx) error {
		var configured bool
		if err := tx.QueryRow(ctx, primaryStateSQL).Scan(&tl, &configured); err != nil {
			return err
		}
		return recordTimeline(ctx, tx, tl, r == ReplicationSync && configured)
	})
	if err != nil {
		return 0, fmt.Errorf("db: acknowledge the primary timeline: %w", err)
	}
	return tl, nil
}

func recordTimeline(ctx context.Context, tx GlobalTx, tl int64, syncVerified bool) error {
	tag, err := tx.Exec(ctx, recordSQL, tl, syncVerified)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNoTimelineRow
	}
	return nil
}

// decidePromotion decides the start-up check: the primary's timeline, the
// acknowledged one (nil before the first start) and whether sync was
// verified on it (ackSync), and whether the primary runs verified sync
// (configured). record says whether timeline becomes the acknowledged one,
// with Sync as its verification.
func decidePromotion(r Replication, timeline int64, ack *int64, ackSync, configured bool) (out Promotion, record bool) {
	out.Timeline = timeline
	if r == ReplicationSync {
		out.Sync, out.Unverified = configured, !configured
	}
	if ack == nil {
		return out, true
	}
	out.Acknowledged = *ack
	switch {
	case *ack == timeline:
		// The same timeline: its verification is what this start found.
		return out, true
	case ackSync && out.Sync:
		// Sync at both ends: the standby applied every commit.
		return out, true
	default:
		out.Hold = true
		return out, false
	}
}

// ErrTimelineChanged reports a promotion the running process cannot
// accept (G0 M19 D213, HR-496): the database moved to a new timeline and
// synchronous replication was not verified at both ends. From then on the
// pool serves nothing, not even its connections opened before, so nothing
// is decided; /readyz and /livez fail, and the orchestrator restarts the
// process into the start-up hold until `keys bump-epochs`.
var ErrTimelineChanged = errors.New("db: the primary was promoted without verified synchronous replication; restart into the maintenance hold")

// timelineWatch is the running process's view of the primary's timeline,
// armed by CheckPromotion. Every new connection reads the timeline again:
// the same one passes; a new one passes only when this process verified
// sync at start and the new primary verifies it too, and is then
// recorded; anything else breaks the pool for good (D213): every
// connection is refused at acquire and the idle ones are closed (D218).
type timelineWatch struct {
	mu       sync.Mutex
	armed    bool
	timeline int64
	sync     bool // sync verified at start
	broken   bool
	// onBreak closes the pool's idle connections when the watch breaks.
	onBreak func()
}

func (w *timelineWatch) arm(p Promotion) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.armed, w.timeline, w.sync = true, p.Timeline, p.Sync
}

func (w *timelineWatch) isBroken() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.broken
}

// observe decides one connection's timeline; record says the caller must
// record tl as the acknowledged timeline before using the connection.
func (w *timelineWatch) observe(tl int64, newSync bool) (record bool, err error) {
	w.mu.Lock()
	switch {
	case !w.armed:
		w.mu.Unlock()
		return false, nil
	case w.broken:
		w.mu.Unlock()
		return false, ErrTimelineChanged
	case tl == w.timeline:
		w.mu.Unlock()
		return false, nil
	case w.sync && newSync:
		w.timeline = tl
		w.mu.Unlock()
		return true, nil
	}
	w.broken = true
	onBreak := w.onBreak
	w.mu.Unlock()
	if onBreak != nil {
		onBreak()
	}
	return false, ErrTimelineChanged
}

// prepare runs before a pooled connection is handed out (PrepareConn):
// after a break, the connection is destroyed and the caller refused.
func (w *timelineWatch) prepare(context.Context, *pgx.Conn) (bool, error) {
	if w.isBroken() {
		return false, ErrTimelineChanged
	}
	return true, nil
}

// check runs on every new connection (AfterConnect).
func (w *timelineWatch) check(ctx context.Context, conn *pgx.Conn) error {
	w.mu.Lock()
	armed := w.armed
	w.mu.Unlock()
	if !armed {
		return nil
	}
	var tl int64
	var configured bool
	if err := conn.QueryRow(ctx, primaryStateSQL).Scan(&tl, &configured); err != nil {
		return err
	}
	record, err := w.observe(tl, configured)
	if err != nil || !record {
		return err
	}
	// The new primary applied every commit before it was promoted, so
	// nothing was lost: record its timeline, verified, so a restart does
	// not hold.
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, globalSetup, string(GlobalFailover)); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, recordSQL, tl, true)
		if err == nil && tag.RowsAffected() != 1 {
			err = ErrNoTimelineRow
		}
		return err
	})
}

// TimelineChanged reports that the pool saw a promotion it could not
// accept and refuses every connection (D213): the process is not ready
// and not live, and must restart into the start-up hold.
func (p *Pool) TimelineChanged() bool { return p != nil && p.timeline.isBroken() }

// beginner begins transactions on the pool and survives the pooled
// connections a failover leaves dead (D202): the pool hands out an idle
// connection to the old primary only to find it closed, and would do so
// once for each. When BEGIN fails that way nothing ran, so the idle
// connections are dropped and BEGIN is tried once more on a new one, which
// reaches the read-write primary or fails closed. After a break nothing
// begins (D218).
type beginner struct {
	p *pgxpool.Pool
	w *timelineWatch
}

func (b beginner) BeginTx(ctx context.Context, o pgx.TxOptions) (pgx.Tx, error) {
	if b.w.isBroken() {
		return nil, ErrTimelineChanged
	}
	tx, err := b.p.BeginTx(ctx, o)
	if err == nil || ctx.Err() != nil || !lostConn(err) {
		return tx, err
	}
	b.p.Reset()
	return b.p.BeginTx(ctx, o)
}

// dropDeadConns drops the pool's idle connections after a transaction
// failed because its connection was lost, so the next one starts afresh.
func (p *Pool) dropDeadConns(err error) error {
	if err != nil && lostConn(err) {
		p.pool.Reset()
	}
	return err
}

// lostConn reports an error of the connection itself (closed, reset, gone),
// never one the server answered.
func lostConn(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return false
	}
	var opErr *net.OpError
	return errors.Is(err, pgconn.ErrConnClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.As(err, &opErr)
}
