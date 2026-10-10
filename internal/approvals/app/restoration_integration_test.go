// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// suspended suspends the fixture's agent (from DISCOVERED, as it was) and
// binds carol as Responder, a month ago.
func (f *fx) suspended() {
	f.t.Helper()
	f.exec("UPDATE pc.agents SET state = 'SUSPENDED', suspended_from = 'DISCOVERED' WHERE id = $1", f.agent)
	f.exec(`INSERT INTO pc.agent_changes (org_id, id, agent_id, kind, actor, reason) VALUES ($1, $2, $3, 'agent.suspended', 'test', 'leak')`,
		f.org, ids.NewV7(), f.agent)
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
		VALUES ($1, $2, 'responder', $3, 'ORG', $4, now() - interval '30 days')`, f.org, ids.NewV7(), f.carol.id, "user:"+f.alice.id.String())
}

// owner is a caller holding Agent Owner (agent.manage) at org scope.
func (f *fx) owner(p person) context.Context {
	return f.as(p, td.Binding{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}})
}

// TestHR176_ARestorationNeedsAnotherRestorersKey (decision 11): asking needs
// agent.manage and a suspended agent; the request is bound and waits 24
// hours with its RESTORATION entry; the requester and a mere approver cannot
// decide it; a Responder's approval returns the agent to the state it was
// suspended from in the same transaction.
func TestHR176_ARestorationNeedsAnotherRestorersKey(t *testing.T) {
	f := newFx(t, 1)
	if _, _, err := f.svc.RequestRestoration(f.owner(f.alice), f.agent, "fixed"); !errors.Is(err, approvals.ErrNotSuspended) {
		t.Fatalf("an agent that is not suspended: %v", err)
	}
	f.suspended()
	if _, _, err := f.svc.RequestRestoration(f.as(f.bob), f.agent, "fixed"); err == nil {
		t.Fatal("a caller without agent.manage asked for a restoration")
	}
	if _, _, err := f.svc.RequestRestoration(f.owner(f.alice), f.agent, ""); !errors.Is(err, approvals.ErrBadReason) {
		t.Fatalf("no reason: %v", err)
	}
	r, entry, err := f.svc.RequestRestoration(f.owner(f.alice), f.agent, "the leaked key was rotated")
	if err != nil || r.SubjectKind != "RESTORATION" || r.State != "PENDING" || r.RequestedBy == nil || *r.RequestedBy != f.alice.id {
		t.Fatalf("request: %+v, %v", r, err)
	}
	if hours := time.Until(r.DeadlineAt).Hours(); hours < 23 || hours > 24 {
		t.Fatalf("deadline in %.1f hours", hours)
	}
	if again, againEntry, err := f.svc.RequestRestoration(f.owner(f.alice), f.agent, "again"); err != nil || again.ID != r.ID || entry.IsZero() || againEntry != entry {
		t.Fatalf("a second request: %v, %v", again.ID, err)
	}
	if s := f.str(`SELECT state || ' ' || requested_by || ' ' || (deadline_at = $2)::text FROM pc.waitlist_entries
		WHERE kind = 'RESTORATION' AND subject_id = $1`, r.ID, r.DeadlineAt); s != "OPEN user:"+f.alice.id.String()+" true" {
		t.Fatalf("entry %q", s)
	}
	if _, err := f.svc.RequestEvidence(f.as(f.carol), r.ID, "WHY_NEEDED", "", time.Now().Add(time.Hour)); !errors.Is(err, approvals.ErrNoEvidence) {
		t.Fatalf("evidence for a restoration: %v", err)
	}

	// The requester, even holding the role, and an approver cannot decide.
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
		VALUES ($1, $2, 'security_admin', $3, 'ORG', $4, now() - interval '30 days')`, f.org, ids.NewV7(), f.alice.id, "user:"+f.bob.id.String())
	for _, p := range []person{f.alice, f.bob} {
		if _, err := f.svc.BeginApproval(context.Background(), f.org, approvals.Responder{User: p.id, Browser: p.browser}, r.ID); !errors.Is(err, approvals.ErrNotEligible) {
			t.Fatalf("%s: %v", p.id, err)
		}
	}
	got, err := f.approve(f.carol, r.ID)
	if err != nil || got.State != "CONSUMED" {
		t.Fatalf("the responder's approval: %s, %v", got.State, err)
	}
	if s := f.str("SELECT state || ' ' || coalesce(suspended_from, '-') FROM pc.agents WHERE id = $1", f.agent); s != "DISCOVERED -" {
		t.Fatalf("agent %q", s)
	}
	if s := f.str("SELECT count(*)::text FROM pc.agent_changes WHERE agent_id = $1 AND kind = 'agent.restored'", f.agent); s != "1" {
		t.Fatalf("%s restored changes", s)
	}
	if s := f.str("SELECT state FROM pc.waitlist_entries WHERE kind = 'RESTORATION' AND subject_id = $1", r.ID); s != "APPROVED" {
		t.Fatalf("entry %s", s)
	}
}

// TestHR176_AChangedAgentIsNotRestored: a restoration binds the agent's
// recorded changes; after another change, the approval is refused and the
// janitor invalidates the request.
func TestHR176_AChangedAgentIsNotRestored(t *testing.T) {
	f := newFx(t, 1)
	f.suspended()
	r, _, err := f.svc.RequestRestoration(f.owner(f.alice), f.agent, "fixed")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO pc.agent_changes (org_id, id, agent_id, kind, actor) VALUES ($1, $2, $3, 'agent.updated', 'test')`,
		f.org, ids.NewV7(), f.agent)
	if _, err := f.approve(f.carol, r.ID); !errors.Is(err, approvals.ErrAgentChanged) {
		t.Fatalf("approving a changed agent: %v", err)
	}
	if s := f.str("SELECT state FROM pc.agents WHERE id = $1", f.agent); s != "SUSPENDED" {
		t.Fatalf("agent %s", s)
	}
	f.sweep()
	if s := f.str("SELECT state || ' ' || end_reason FROM pc.approval_requests WHERE id = $1", r.ID); s != "INVALIDATED AGENT_CHANGED" {
		t.Fatalf("request %q", s)
	}
}
