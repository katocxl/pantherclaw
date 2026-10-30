// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
)

// Promotion detection (G0 M19 D202, D207, HR-496). A promotion moves the
// database to a new timeline. Behind a synchronous standby that applied
// every commit (synchronous_commit=remote_apply), nothing committed is
// lost; behind an asynchronous one, revocations, containment changes and
// budget reservations may be. So a server that finds a timeline other
// than the acknowledged one in pc.db_primary_timeline, without verified
// synchronous replication, starts in the maintenance hold, and `keys
// bump-epochs` acknowledges the new timeline once every epoch is raised.

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
	// Hold is set when the timeline moved without effective sync: the
	// server must start in the maintenance hold.
	Hold bool
}

// ErrNoTimelineRow reports a database without the singleton row of
// pc.db_primary_timeline (migration 00230): the check cannot be made, so
// the server does not start.
var ErrNoTimelineRow = errors.New("db: pc.db_primary_timeline has no row; run `migrate up`")

// currentTimeline reads the timeline WAL is written on now; it moves the
// moment a standby is promoted, unlike the last checkpoint's.
const currentTimeline = `SELECT ('x' || substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8))::bit(32)::bigint`

// CheckPromotion compares the primary's timeline with the acknowledged one
// for declared replication r. A first start records the timeline and does
// not hold; a moved timeline holds unless replication is effectively sync,
// in which case the new timeline is recorded.
func (p *Pool) CheckPromotion(ctx context.Context, r Replication) (Promotion, error) {
	if !r.Valid() {
		return Promotion{}, fmt.Errorf("db: replication %q (use async or sync)", r)
	}
	var out Promotion
	err := p.InGlobalTx(ctx, GlobalFailover, func(ctx context.Context, tx GlobalTx) error {
		var commit, standbys string
		if err := tx.QueryRow(ctx, currentTimeline+`, current_setting('synchronous_commit'),
			current_setting('synchronous_standby_names')`).Scan(&out.Timeline, &commit, &standbys); err != nil {
			return err
		}
		var ack *int64
		switch err := tx.QueryRow(ctx, `SELECT timeline FROM pc.db_primary_timeline FOR UPDATE`).Scan(&ack); {
		case IsNoRows(err):
			return ErrNoTimelineRow
		case err != nil:
			return err
		}
		var record bool
		out, record = decidePromotion(r, out.Timeline, ack, commit, standbys)
		if record {
			return recordTimeline(ctx, tx, out.Timeline)
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
// not hold. It returns the timeline.
func (p *Pool) AcknowledgeTimeline(ctx context.Context) (int64, error) {
	var tl int64
	err := p.InGlobalTx(ctx, GlobalFailover, func(ctx context.Context, tx GlobalTx) error {
		if err := tx.QueryRow(ctx, currentTimeline).Scan(&tl); err != nil {
			return err
		}
		return recordTimeline(ctx, tx, tl)
	})
	if err != nil {
		return 0, fmt.Errorf("db: acknowledge the primary timeline: %w", err)
	}
	return tl, nil
}

func recordTimeline(ctx context.Context, tx GlobalTx, tl int64) error {
	tag, err := tx.Exec(ctx, `UPDATE pc.db_primary_timeline SET timeline = $1, update_time = now()`, tl)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNoTimelineRow
	}
	return nil
}

// decidePromotion decides the start-up check (D207): the primary's
// timeline, the acknowledged one (nil before the first start) and the
// primary's synchronous_commit and synchronous_standby_names. record says
// whether timeline becomes the acknowledged one.
func decidePromotion(r Replication, timeline int64, ack *int64, commit, standbys string) (out Promotion, record bool) {
	out.Timeline = timeline
	if r == ReplicationSync {
		out.Sync = commit == "remote_apply" && strings.TrimSpace(standbys) != ""
		out.Unverified = !out.Sync
	}
	switch {
	case ack == nil:
		return out, true
	case *ack == timeline:
		out.Acknowledged = *ack
		return out, false
	case out.Sync:
		out.Acknowledged = *ack
		return out, true
	default:
		out.Acknowledged, out.Hold = *ack, true
		return out, false
	}
}

// ErrTimelineChanged reports a promotion the running process cannot
// accept (G0 M19 D213, HR-496): the database moved to a new timeline and
// synchronous replication was not verified at both ends. From then on the
// pool refuses every connection, so nothing is decided; /readyz and
// /livez fail, and the orchestrator restarts the process into the start-up
// hold until `keys bump-epochs`.
var ErrTimelineChanged = errors.New("db: the primary was promoted without verified synchronous replication; restart into the maintenance hold")

// timelineWatch is the running process's view of the primary's timeline,
// armed by CheckPromotion. Every new connection reads the timeline again:
// the same one passes; a new one passes only when this process verified
// sync at start and the new primary verifies it too, and is then
// recorded; anything else breaks the pool for good (D213).
type timelineWatch struct {
	mu       sync.Mutex
	armed    bool
	timeline int64
	sync     bool // sync verified at start
	broken   bool
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
	defer w.mu.Unlock()
	switch {
	case !w.armed:
		return false, nil
	case w.broken:
		return false, ErrTimelineChanged
	case tl == w.timeline:
		return false, nil
	case w.sync && newSync:
		w.timeline = tl
		return true, nil
	default:
		w.broken = true
		return false, ErrTimelineChanged
	}
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
	var commit, standbys string
	if err := conn.QueryRow(ctx, currentTimeline+`, current_setting('synchronous_commit'),
		current_setting('synchronous_standby_names')`).Scan(&tl, &commit, &standbys); err != nil {
		return err
	}
	record, err := w.observe(tl, commit == "remote_apply" && strings.TrimSpace(standbys) != "")
	if err != nil || !record {
		return err
	}
	// The new primary applied every commit before it was promoted, so
	// nothing was lost: record its timeline, so a restart does not hold.
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, globalSetup, string(GlobalFailover)); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE pc.db_primary_timeline SET timeline = $1, update_time = now()`, tl)
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
