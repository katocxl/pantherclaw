// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// apbFresh adds an enabled user with a key and an approver binding at the
// team, all made a moment ago; the binding is the user's own when self.
func apbFresh(f *rfx, accountAge string, self bool) ids.UUID {
	f.t.Helper()
	u := ids.NewV7()
	f.exec(`INSERT INTO pc.users (org_id, id, issuer, subject, created_at) VALUES ($1, $2, 'https://idp.test', $3, now() - $4::interval)`,
		f.org, u, u.String(), accountAge)
	f.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
		attestation_fmt, name, created_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', now() - $6::interval)`,
		f.org, ids.NewV7(), u, u[:], append(append([]byte{}, u[:]...), u[:]...), accountAge)
	by := "user:" + f.ben.String()
	if self {
		by = "user:" + u.String()
	}
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, team_id, created_by)
		VALUES ($1, $2, 'approver', $3, 'TEAM', $4, $5)`, f.org, ids.NewV7(), u, f.team, by)
	return u
}

// apbApprovers returns who of people may approve request now: those for
// whom the approval page would start the BINDING ceremony.
func apbApprovers(f *rfx, svc *approvals.Service, request ids.UUID, people []ids.UUID) []ids.UUID {
	f.t.Helper()
	var out []ids.UUID
	for _, u := range people {
		_, err := svc.BeginApproval(context.Background(), f.org, approvals.Responder{User: u, Browser: ids.NewV7()}, request)
		switch {
		case err == nil:
			out = append(out, u)
		case !errors.Is(err, approvals.ErrNotEligible):
			f.t.Fatalf("%s: %v", u, err)
		}
	}
	return out
}

// TestT061_RoutingAndEscalationNeverMakeAnyoneADecider: T-061 — a
// two-person hold for an agent whose owner launched the run. The launcher
// holds the Approver role, someone holds it on another team, an admin
// holds none, a colleague granted it to himself a moment ago and a
// sock-puppet account was made a moment ago with it. Routing, both
// escalation steps and an assignment run; who may approve is the same
// before and after: never the launcher, the self-granted or the new
// account, and the launcher, the admin and the other team are never told
// as deciders. (The self-granted and the new account hold the role, so
// they are told and may decline, which grants nothing, HR-172.)
// TestHR173_* cover each step; TestHR035_CooldownsHold and TestHR036_*
// the eligibility rules.
func TestT061_RoutingAndEscalationNeverMakeAnyoneADecider(t *testing.T) {
	f := newRFx(t)
	near, org := f.person("approver", "TEAM"), f.person("approver", "ORG")
	f.bind(f.ann, "approver", "TEAM")
	admin := f.person("org_admin", "ORG")
	otherTeam := ids.NewV7()
	f.exec("INSERT INTO pc.teams (org_id, id, business_unit_id, slug, name) VALUES ($1, $2, $3, 'payouts', 'Payouts')", f.org, otherTeam, f.bu)
	stranger := f.person("auditor", "ORG")
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, team_id, created_by, created_at)
		VALUES ($1, $2, 'approver', $3, 'TEAM', $4, 'test', now() - interval '30 days')`, f.org, ids.NewV7(), stranger, otherTeam)
	self, puppet := apbFresh(f, "30 days", true), apbFresh(f, "1 minute", false)
	entry, request := f.hold()
	f.d.AdminExec(t, `UPDATE pc.approval_requests SET requirements = '[{"kind":"approval","role":"approver","count":2,"sources":[]}]'
		WHERE id = $1`, request)

	svc := &approvals.Service{Pool: f.p}
	people := []ids.UUID{near, org, f.ann, admin, stranger, self, puppet}
	before := apbApprovers(f, svc, request, people)
	if !slices.Equal(before, []ids.UUID{near, org}) {
		t.Fatalf("approvers before routing %v, want %v", before, []ids.UUID{near, org})
	}
	f.route()
	f.due(entry)
	f.route()
	f.due(entry)
	f.route()
	routes := f.routes(entry)
	for _, never := range []ids.UUID{f.ann, admin, stranger} {
		if slices.Contains(routes, "decider:"+never.String()) {
			t.Errorf("%s was told as a decider: %v", never, routes)
		}
	}
	if !slices.Contains(routes, "owner:"+f.ann.String()) || !slices.Contains(routes, "decider:"+org.String()) {
		t.Fatalf("the escalation did not reach the owner and the org: %v", routes)
	}
	if _, err := f.w.Assign(f.as(f.ann, td.RoleApprover), entry, false); !errors.Is(err, waitlist.ErrNotDecider) {
		t.Fatalf("the launcher taking the entry: %v", err)
	}
	if _, err := f.w.Assign(f.as(near, td.RoleApprover), entry, false); err != nil {
		t.Fatal(err)
	}
	if after := apbApprovers(f, svc, request, people); !slices.Equal(after, before) {
		t.Fatalf("approvers after routing, escalation and assignment %v, want %v", after, before)
	}
	if s := strings.Join(f.sentTo(f.ann), " "); strings.Contains(s, "approval.requested") || strings.Contains(s, "approval.reminder") {
		t.Fatalf("the launcher was asked to decide: %s", s)
	}
}

// TestT061_AFailedDeliveryOrAMissedDeadlineIsNeverConsent: T-061 — every
// notice of a hold fails (an attacker floods or blocks the deciders'
// mail) and nobody answers. The entry is marked DELIVERY_FAILING and the
// agent's wait handle says PENDING; once the deadline passes the handle
// says EXPIRED by the database clock, before any janitor runs, and the
// janitor then ends the request and its entry as EXPIRED with no response
// recorded and nothing left to approve. The DENY at resubmission is
// TestHR039_AnExpiredHoldEndsAsDenyAtUse; the marking
// TestHR039_AFailedDeliveryMarksTheEntryAndDecidesNothing.
func TestT061_AFailedDeliveryOrAMissedDeadlineIsNeverConsent(t *testing.T) {
	f := newRFx(t)
	near := f.person("approver", "TEAM")
	entry, request := f.hold()
	f.route()
	f.n.failed = []ids.UUID{entry}
	f.route()
	waits := approvals.NewWaits(f.p, 0, 0, nil)
	ctx := context.Background()
	if v, err := waits.Read(ctx, f.org, f.instance, f.run, f.txn); err != nil || v.State != apdomain.WaitPending {
		t.Fatalf("while deliveries fail: %+v, %v", v, err)
	}
	var health string
	f.d.AdminQueryRow(t, "SELECT routing_health FROM pc.waitlist_entries WHERE id = $1", []any{entry}, &health)
	if health != "DELIVERY_FAILING" {
		t.Fatalf("health %s", health)
	}

	f.d.AdminExec(t, `UPDATE pc.approval_requests SET created_at = now() - interval '2 hours',
		deadline_at = date_trunc('second', now()) - interval '1 second' WHERE id = $1`, request)
	v, err := waits.Read(ctx, f.org, f.instance, f.run, f.txn)
	if err != nil || v.State != apdomain.WaitExpired || v.Code != apdomain.ReasonApprovalExpired || !v.Final() {
		t.Fatalf("after the deadline: %+v, %v", v, err)
	}
	if s, err := approvals.SweepOrg(ctx, f.p, nil, f.org); err != nil || s.Expired != 1 {
		t.Fatalf("janitor: %+v, %v", s, err)
	}
	var state, entryState string
	var responses int
	f.d.AdminQueryRow(t, `SELECT r.state, e.state, (SELECT count(*) FROM pc.approval_responses x WHERE x.request_id = r.id)::int
		FROM pc.approval_requests r JOIN pc.waitlist_entries e ON e.subject_id = r.id WHERE r.id = $1`, []any{request}, &state, &entryState, &responses)
	if state != "EXPIRED" || entryState != "EXPIRED" || responses != 0 {
		t.Fatalf("request %s, entry %s, %d responses", state, entryState, responses)
	}
	svc := &approvals.Service{Pool: f.p}
	if _, err := svc.BeginApproval(ctx, f.org, approvals.Responder{User: near, Browser: ids.NewV7()}, request); !errors.Is(err, approvals.ErrNotWaiting) {
		t.Fatalf("approving after the deadline: %v", err)
	}
}
