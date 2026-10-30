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

// TestHR496_PromotionHoldDecision: a moved timeline holds unless declared
// sync is confirmed by the primary's settings; a first start records the
// timeline and does not hold (G0 M19 D207).
// Covers: PN-010.7
func TestHR496_PromotionHoldDecision(t *testing.T) {
	one, two := int64(1), int64(2)
	cases := []struct {
		name             string
		r                Replication
		ack              *int64
		commit, standbys string
		hold, record     bool
		unverified       bool
	}{
		{name: "first start records the timeline", r: ReplicationAsync, record: true},
		{name: "first start with sync records the timeline", r: ReplicationSync, commit: "remote_apply", standbys: "FIRST 1 (standby)", record: true},
		{name: "same timeline", r: ReplicationAsync, ack: &two},
		{name: "async promotion holds", r: ReplicationAsync, ack: &one, commit: "remote_apply", standbys: "FIRST 1 (standby)", hold: true},
		{name: "declared sync without a standby holds", r: ReplicationSync, ack: &one, commit: "remote_apply", standbys: " ", hold: true, unverified: true},
		{name: "declared sync without remote_apply holds", r: ReplicationSync, ack: &one, commit: "on", standbys: "FIRST 1 (standby)", hold: true, unverified: true},
		{name: "verified sync records the new timeline", r: ReplicationSync, ack: &one, commit: "remote_apply", standbys: "FIRST 1 (standby)", record: true},
	}
	for _, c := range cases {
		p, record := decidePromotion(c.r, 2, c.ack, c.commit, c.standbys)
		if p.Hold != c.hold || record != c.record || p.Unverified != c.unverified || p.Timeline != 2 {
			t.Errorf("%s: hold=%v record=%v unverified=%v timeline=%d", c.name, p.Hold, record, p.Unverified, p.Timeline)
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
