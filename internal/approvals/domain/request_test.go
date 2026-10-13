// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
)

// TestHR171_RequestLifecycle: final states are final, a changed binding
// supersedes (never updates), an approved request can only be consumed,
// fall back to PENDING after a void, expire or be invalidated, a consumed
// one can only be restored to APPROVED (HR-011), and only a decline or an
// expiry ends the transaction as DENY.
func TestHR171_RequestLifecycle(t *testing.T) {
	for _, s := range []domain.State{
		domain.StateDeclined, domain.StateExpired, domain.StateInvalidated, domain.StateSuperseded,
	} {
		if !domain.Lifecycle.Terminal(s) || s.Live() {
			t.Errorf("%s is not final", s)
		}
	}
	if next := domain.Lifecycle.Next(domain.StateConsumed); len(next) != 1 || next[0] != domain.StateApproved ||
		domain.StateConsumed.Live() {
		t.Errorf("a consumed request waits for nothing and may only be restored: next %v", next)
	}
	for _, c := range []struct {
		from, to domain.State
		ok       bool
	}{
		{domain.StatePending, domain.StateApproved, true},
		{domain.StatePending, domain.StateConsumed, false},
		{domain.StateApproved, domain.StateConsumed, true},
		{domain.StateApproved, domain.StatePending, true},
		{domain.StateApproved, domain.StateDeclined, false},
		{domain.StateEvidenceRequested, domain.StateApproved, false},
		{domain.StateEvidenceRequested, domain.StatePending, true},
		{domain.StateDeclined, domain.StatePending, false},
		{domain.StateConsumed, domain.StateApproved, true},
		{domain.StateConsumed, domain.StatePending, false},
		{domain.StateExpired, domain.StateApproved, false},
	} {
		if domain.Lifecycle.Can(c.from, c.to) != c.ok {
			t.Errorf("%s → %s allowed=%v", c.from, c.to, !c.ok)
		}
	}
	if !domain.Terminal(domain.StateDeclined) || !domain.Terminal(domain.StateExpired) ||
		domain.Terminal(domain.StateSuperseded) || domain.Terminal(domain.StateInvalidated) {
		t.Error("only a decline or an expiry ends the transaction")
	}
}

// TestHR039_ExpiryIsEnforcedAtUse: whatever the stored state, a live
// request past its deadline, evidence deadline or consume-by time is
// expired by the database clock, with or without the janitor.
func TestHR039_ExpiryIsEnforcedAtUse(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	before, after := now.Add(time.Minute), now.Add(-time.Second)
	for _, c := range []struct {
		name  string
		state domain.State
		times domain.Times
		want  domain.State
	}{
		{"pending before the deadline", domain.StatePending, domain.Times{Deadline: before}, domain.StatePending},
		{"pending at the deadline", domain.StatePending, domain.Times{Deadline: now}, domain.StateExpired},
		{"evidence overdue", domain.StateEvidenceRequested, domain.Times{Deadline: before, EvidenceDeadline: &after}, domain.StateExpired},
		{"evidence in time", domain.StateEvidenceRequested, domain.Times{Deadline: before, EvidenceDeadline: &before}, domain.StateEvidenceRequested},
		{"approved, not used in time", domain.StateApproved, domain.Times{Deadline: before, ConsumeBy: &after}, domain.StateExpired},
		{"approved, past the deadline", domain.StateApproved, domain.Times{Deadline: after, ConsumeBy: &before}, domain.StateExpired},
		{"approved in time", domain.StateApproved, domain.Times{Deadline: before, ConsumeBy: &before}, domain.StateApproved},
		{"declined stays declined", domain.StateDeclined, domain.Times{Deadline: after}, domain.StateDeclined},
	} {
		got, reason := domain.At(c.state, c.times, now)
		if got != c.want || (got == domain.StateExpired && c.state.Live() && reason != domain.EndExpired) {
			t.Errorf("%s: %s %q, want %s", c.name, got, reason, c.want)
		}
	}
}

// TestHR174_WaitersSeeStatesOnly: the wait state is derived from the state
// and the end reason only.
func TestHR174_WaitersSeeStatesOnly(t *testing.T) {
	for _, c := range []struct {
		s      domain.State
		reason string
		want   string
	}{
		{domain.StatePending, "", domain.WaitPending},
		{domain.StateApproved, "", domain.WaitReady},
		{domain.StateDeclined, domain.EndDeclined, domain.WaitDeclined},
		{domain.StateDeclined, domain.EndNarrowerProposed, domain.WaitNarrowerProposed},
		{domain.StateInvalidated, domain.EndGrantRevoked, domain.WaitInvalidated},
		{domain.StateConsumed, "", domain.WaitConsumed},
	} {
		if got := domain.WaitState(c.s, c.reason); got != c.want {
			t.Errorf("%s/%s: %s, want %s", c.s, c.reason, got, c.want)
		}
	}
}
