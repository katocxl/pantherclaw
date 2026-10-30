// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestHR496_PromotionHoldDecision: a moved timeline holds unless sync was
// verified both on the acknowledged timeline and on the new primary; a
// first start, or the same timeline, records what this start verified
// (G0 M19 D207, D218).
// Covers: PN-010.7
func TestHR496_PromotionHoldDecision(t *testing.T) {
	one, two := int64(1), int64(2)
	cases := []struct {
		name                string
		r                   Replication
		ack                 *int64
		ackSync, configured bool
		hold, record        bool
		sync, unverified    bool
	}{
		{name: "first start records the timeline", r: ReplicationAsync, record: true},
		{name: "first start with verified sync", r: ReplicationSync, configured: true, record: true, sync: true},
		{name: "same timeline records this start's verification", r: ReplicationAsync, ack: &two, ackSync: true, record: true},
		{name: "async promotion holds", r: ReplicationAsync, ack: &one, ackSync: true, configured: true, hold: true},
		{name: "declared sync the new primary does not confirm holds", r: ReplicationSync, ack: &one, ackSync: true, hold: true, unverified: true},
		{name: "new primary configured sync, old timeline not verified, holds", r: ReplicationSync, ack: &one, configured: true, hold: true, sync: true},
		{name: "sync verified at both ends records the new timeline", r: ReplicationSync, ack: &one, ackSync: true, configured: true, record: true, sync: true},
	}
	for _, c := range cases {
		p, record := decidePromotion(c.r, 2, c.ack, c.ackSync, c.configured)
		if p.Hold != c.hold || record != c.record || p.Sync != c.sync || p.Unverified != c.unverified || p.Timeline != 2 {
			t.Errorf("%s: hold=%v record=%v sync=%v unverified=%v timeline=%d", c.name, p.Hold, record, p.Sync, p.Unverified, p.Timeline)
		}
		if p.Hold && p.Acknowledged != 1 {
			t.Errorf("%s: acknowledged = %d, want 1", c.name, p.Acknowledged)
		}
	}
	if Replication("semi").Valid() || !ReplicationSync.Valid() || !ReplicationAsync.Valid() {
		t.Fatal("Replication.Valid")
	}
}

// TestHR496_RunningProcessRefusesAnUnverifiedPromotion: while running, a
// new timeline is accepted (and recorded) only when sync was verified at
// start and on the new primary; otherwise every later connection is
// refused, the same timeline included, until a restart (G0 M19 D213).
// Covers: PN-010.7
func TestHR496_RunningProcessRefusesAnUnverifiedPromotion(t *testing.T) {
	var unarmed timelineWatch
	if rec, err := unarmed.observe(9, false); rec || err != nil {
		t.Fatalf("unarmed watch: %v %v", rec, err)
	}
	if (*timelineWatch)(nil).isBroken() || (&Pool{}).TimelineChanged() {
		t.Fatal("a pool without a watch reports a changed timeline")
	}
	cases := []struct {
		name               string
		startSync, newSync bool
		accept             bool
	}{
		{name: "async promotion while running", startSync: false, newSync: true},
		{name: "sync at both ends", startSync: true, newSync: true, accept: true},
		{name: "sync promotion to an unverified primary", startSync: true, newSync: false},
	}
	for _, c := range cases {
		w := &timelineWatch{}
		w.arm(Promotion{Timeline: 1, Sync: c.startSync})
		if rec, err := w.observe(1, false); rec || err != nil {
			t.Fatalf("%s: same timeline: %v %v", c.name, rec, err)
		}
		rec, err := w.observe(2, c.newSync)
		if c.accept {
			if !rec || err != nil {
				t.Fatalf("%s: %v %v, want accepted and recorded", c.name, rec, err)
			}
			w.accept(2)
			if rec, err := w.observe(2, false); rec || err != nil {
				t.Fatalf("%s: the accepted timeline again: %v %v", c.name, rec, err)
			}
			continue
		}
		if !errors.Is(err, ErrTimelineChanged) || rec || !w.isBroken() {
			t.Fatalf("%s: %v %v broken=%v, want refused", c.name, rec, err, w.isBroken())
		}
		if _, err := w.observe(1, true); !errors.Is(err, ErrTimelineChanged) {
			t.Fatalf("%s: a later connection was accepted: %v", c.name, err)
		}
	}
}

// TestHR496_AHeldStartNeverVouchesForTheNextPromotion: T1 unverified, then
// T2 starts in the hold on a primary configured sync, then T3 stays held:
// sync verified only on the new primary carries nothing forward (G0 M19
// D221).
// Covers: PN-010.7
func TestHR496_AHeldStartNeverVouchesForTheNextPromotion(t *testing.T) {
	one := int64(1)
	t2, record := decidePromotion(ReplicationSync, 2, &one, false, true)
	if !t2.Hold || record {
		t.Fatalf("T2 = %+v record=%v, want the hold, unrecorded", t2, record)
	}
	w := &timelineWatch{}
	w.arm(t2)
	if rec, err := w.observe(3, true); rec || !errors.Is(err, ErrTimelineChanged) || !w.isBroken() {
		t.Fatalf("T3 = %v %v broken=%v, want refused", rec, err, w.isBroken())
	}
	// Restarted on T3 before anyone acknowledged: the row still says T1.
	if t3, record := decidePromotion(ReplicationSync, 3, &one, false, true); !t3.Hold || record {
		t.Fatalf("restart on T3 = %+v record=%v, want the hold", t3, record)
	}
}

// TestLostConnDropsOnlyDeadConnections: only errors of the connection
// itself make the pool drop its idle connections and retry BEGIN, never an
// answer from the server or an application error (G0 M19 D202).
// Covers: PN-010.7
func TestLostConnDropsOnlyDeadConnections(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("begin: %w", pgconn.ErrConnClosed), io.ErrUnexpectedEOF, fmt.Errorf("x: %w", io.EOF),
		&net.OpError{Op: "read", Err: errors.New("connection reset by peer")}, net.ErrClosed,
	} {
		if !lostConn(err) {
			t.Errorf("%v: not a lost connection", err)
		}
	}
	for _, err := range []error{nil, ErrLostRace, ErrTimelineChanged, &pgconn.PgError{Code: "25006"}, errors.New("app")} {
		if lostConn(err) {
			t.Errorf("%v: taken for a lost connection", err)
		}
	}
}
