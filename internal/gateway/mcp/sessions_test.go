// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR083_SessionsBindConnectionInstanceKeyAndRun: a session matches a
// request only on its connection, from its instance, with its key, in its
// run (or naming none).
func TestHR083_SessionsBindConnectionInstanceKeyAndRun(t *testing.T) {
	s := session{conn: holdConn, instance: holdInst, jkt: "key-1", run: holdRun}
	in := dispatch.Inbound{Instance: holdInst, JKT: "key-1", Run: holdRun}
	if !s.binds(holdConn, in) {
		t.Fatal("its own request did not match")
	}
	noRun := in
	noRun.Run = ""
	if !s.binds(holdConn, noRun) {
		t.Fatal("a request naming no run did not match")
	}
	other := ids.NewV7().String()
	for name, tc := range map[string]struct {
		conn string
		edit func(*dispatch.Inbound)
	}{
		"connection": {other, func(*dispatch.Inbound) {}},
		"instance":   {holdConn, func(i *dispatch.Inbound) { i.Instance = other }},
		"key":        {holdConn, func(i *dispatch.Inbound) { i.JKT = "key-2" }},
		"run":        {holdConn, func(i *dispatch.Inbound) { i.Run = other }},
	} {
		req := in
		tc.edit(&req)
		if s.binds(tc.conn, req) {
			t.Errorf("another %s matched", name)
		}
	}
}

// TestHR083_SessionsEnd: a session ends after 30 idle minutes, after 8
// hours however busy, when its run expires, and when ended.
func TestHR083_SessionsEnd(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s := newSessions(c.now)
	open := func(runExpires time.Time) string {
		t.Helper()
		id, err := s.open(holdConn, holdInst, "key-1", holdRun, runExpires)
		if err != nil || len(id) != 43 {
			t.Fatalf("open = %q %v", id, err)
		}
		return id
	}
	idle := open(time.Time{})
	c.t = c.t.Add(sessionIdle - time.Second)
	if _, ok, _ := s.get(idle); !ok {
		t.Fatal("ended before its idle time")
	}
	c.t = c.t.Add(time.Second)
	if _, ok, _ := s.get(idle); ok {
		t.Fatal("an idle session lived on")
	}
	busy := open(time.Time{})
	for range 17 { // 17 × 29 minutes: past 8 hours, never idle
		c.t = c.t.Add(29 * time.Minute)
		s.touch(busy)
	}
	if _, ok, _ := s.get(busy); ok {
		t.Fatal("a session lived beyond 8 hours")
	}
	short := open(c.t.Add(10 * time.Minute))
	c.t = c.t.Add(10 * time.Minute)
	if _, ok, _ := s.get(short); ok {
		t.Fatal("a session outlived its run")
	}
	ended := open(time.Time{})
	s.end(ended)
	if _, ok, _ := s.get(ended); ok {
		t.Fatal("an ended session was found")
	}
	if _, ok, _ := s.get("not-a-session"); ok {
		t.Fatal("an unknown id was found")
	}
}

// TestHR083_AnInstanceKeepsAtMost16Sessions: opening a 17th session ends
// the instance's least recently used one; other instances keep theirs.
func TestHR083_AnInstanceKeepsAtMost16Sessions(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s := newSessions(c.now)
	theirs, err := s.open(holdConn, ids.NewV7().String(), "key-2", holdRun, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var mine []string
	for range maxSessionsPerInstance {
		c.t = c.t.Add(time.Second)
		id, err := s.open(holdConn, holdInst, "key-1", holdRun, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		mine = append(mine, id)
	}
	c.t = c.t.Add(time.Second)
	s.touch(mine[0]) // the oldest is used again; the second becomes the least recent
	if _, err := s.open(holdConn, holdInst, "key-1", holdRun, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.get(mine[1]); ok {
		t.Fatal("the least recently used session was kept")
	}
	for _, id := range append([]string{theirs, mine[0]}, mine[2:]...) {
		if _, ok, _ := s.get(id); !ok {
			t.Fatal("another session was ended")
		}
	}
}
