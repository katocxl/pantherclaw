// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package operations_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// failure records an open owned failure of kind, owned by owner (nil: none).
func (f *fx) failure(kind string, owner *ids.UUID) ids.UUID {
	id := ids.NewV7()
	var ownerType, ownerID any
	state := "OPEN"
	if owner != nil {
		ownerType, ownerID, state = "user", owner.String(), "ASSIGNED"
	}
	f.exec(`INSERT INTO pc.operational_failures (org_id, id, kind, summary, next_step, owner_type, owner_id, deadline, state,
		dedupe_key) VALUES ($1, $2, $3, 'it failed', 'look', $4, $5, now() + interval '1 day', $6, $7)`,
		f.org, id, kind, ownerType, ownerID, state, id.String())
	return id
}

// D38, D73 A3: an automation's owned failures queue as AUTOMATION_EXCEPTION,
// read with automation.read at the org or by the failure's owner, and
// never as protection failures; other owned failures stay protection
// failures read with incident.read.
func TestAutomationExceptionsReachOwnersAndAutomationReaders(t *testing.T) {
	f := newFx(t)
	other := ids.NewV7()
	f.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", f.org, other)
	mine := f.failure("automation.gate_stalled", &f.user)
	theirs := f.failure("automation.loop_stopped", &other)
	plain := f.failure("reflex.edition_lapsed", nil)

	q, err := f.s.GetWorkQueue(f.orgWide())
	if err != nil {
		t.Fatal(err)
	}
	got := kinds(q)
	for _, want := range []string{
		"AUTOMATION_EXCEPTION:" + mine.String(), "AUTOMATION_EXCEPTION:" + theirs.String(), "PROTECTION_FAILURE:" + plain.String(),
	} {
		if !slices.Contains(got, want) {
			t.Errorf("org-wide queue %v lacks %s", got, want)
		}
	}
	if q.Counts[operations.KindAutomationException] != 2 {
		t.Errorf("counts %v", q.Counts)
	}

	// A team-scoped responder holds automation.read only at its team: it
	// sees the exception routed to it, not another owner's.
	q, err = f.s.GetWorkQueue(f.as(td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: f.teamA}))
	if err != nil {
		t.Fatal(err)
	}
	got = kinds(q)
	if !slices.Contains(got, "AUTOMATION_EXCEPTION:"+mine.String()) || slices.Contains(got, "AUTOMATION_EXCEPTION:"+theirs.String()) {
		t.Errorf("team queue %v: want only the caller's own exception", got)
	}
	if !slices.Contains(q.Pending, "automation exceptions: only those routed to you") || q.Whole {
		t.Errorf("pending %v, whole %v", q.Pending, q.Whole)
	}
}
