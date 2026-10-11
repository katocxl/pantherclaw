// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"
	"time"

	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR215_AnAbandonedSessionExpiresAndRevokesItsInstance: a session
// nobody ended (pclaw killed before its first report) is ended EXPIRED by
// the sweep once past its expiry. Its instance, admitted but never bound
// by a report, is revoked, and the containment epoch moves, so the agent's
// active cohort no longer holds it (design decision 9). An open session not
// yet expired is left alone, and a second sweep does nothing.
func TestHR215_AnAbandonedSessionExpiresAndRevokesItsInstance(t *testing.T) {
	w := newWorld(t)
	ctx := w.as(td.RoleAgentOwner)
	in := w.input()
	in.TTL = time.Second
	short, err := w.svc.StartSession(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	inst := w.admit(t, short)
	open, err := w.svc.StartSession(ctx, w.input())
	if err != nil {
		t.Fatal(err)
	}
	epoch := w.count(t, "SELECT coalesce((SELECT epoch FROM pc.org_containment), 0)")
	time.Sleep(1500 * time.Millisecond)

	n, err := w.svc.ExpireSessions(context.Background(), w.org)
	if err != nil || n != 1 {
		t.Fatalf("expired %d, %v", n, err)
	}
	if c := w.count(t, "SELECT count(*) FROM pc.sandbox_sessions WHERE id = $1 AND state = 'EXPIRED' AND ended_at IS NOT NULL", short.Session.ID); c != 1 {
		t.Fatal("the abandoned session is not EXPIRED")
	}
	if c := w.count(t, "SELECT count(*) FROM pc.agent_instances WHERE id = $1 AND state = 'REVOKED'", inst); c != 1 {
		t.Fatal("its instance is not revoked")
	}
	if got := w.count(t, "SELECT coalesce((SELECT epoch FROM pc.org_containment), 0)"); got <= epoch {
		t.Fatalf("epoch %d, was %d", got, epoch)
	}
	if c := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.sandbox.session_expired'"); c != 1 {
		t.Fatalf("%d session_expired audit entries", c)
	}
	if c := w.count(t, "SELECT count(*) FROM pc.sandbox_sessions WHERE id = $1 AND state = 'OPEN'", open.Session.ID); c != 1 {
		t.Fatal("a session not yet expired was ended")
	}
	if n, err := w.svc.ExpireSessions(context.Background(), w.org); err != nil || n != 0 {
		t.Fatalf("a second sweep expired %d, %v", n, err)
	}
}
