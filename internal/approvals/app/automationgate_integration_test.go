// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// gateFx adds to fx an automation (owned by alice), its identity, a
// version and a running execution, and makes dave an Automation Operator
// at org scope a month ago (bob stays a plain Approver).
type gateFx struct {
	*fx
	automation, sa, version, execution ids.UUID
}

func newGateFx(t *testing.T) gateFx {
	t.Helper()
	g := gateFx{fx: newFx(t, 1), automation: ids.NewV7(), sa: ids.NewV7(), version: ids.NewV7(), execution: ids.NewV7()}
	trigger := ids.NewV7()
	err := g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO pc.service_accounts (org_id, id, name, description, created_by, automation_id)
				VALUES ($1, $2, 'automation-refunds', '', 'test', $3)`, []any{g.org, g.sa, g.automation}},
			{`INSERT INTO pc.automations (org_id, id, name, purpose, kind, owner_user_id, service_account_id, created_by)
				VALUES ($1, $2, 'refunds', 'Refunds.', 'AGENT_WORK', $3, $4, $3)`, []any{g.org, g.automation, g.alice.id, g.sa}},
			{`INSERT INTO pc.automation_versions (org_id, id, automation_id, number, definition, digest, created_by)
				VALUES ($1, $2, $3, 1, '{}', $4, $5)`, []any{g.org, g.version, g.automation, make([]byte, 32), g.alice.id}},
			{`INSERT INTO pc.automation_triggers (org_id, id, automation_id, version_id, kind, mode, source_ref, authenticity,
				root_trigger_id, state, occurred_at) VALUES ($1, $2, $3, $4, 'MANUAL', 'SHADOW', 'manual:test', 'USER_SESSION',
				$2, 'SHADOW', now())`, []any{g.org, trigger, g.automation, g.version}},
			{
				`INSERT INTO pc.automation_executions (org_id, id, automation_id, version_id, trigger_id, mode, service_account_id,
				principal_sa_id, trigger_kind, occurred_at, root_trigger_id, deadline_at)
				VALUES ($1, $2, $3, $4, $5, 'SHADOW', $6, $6, 'MANUAL', now(), $5, now() + interval '1 day')`,
				[]any{g.org, g.execution, g.automation, g.version, trigger, g.sa},
			},
			{
				`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
				VALUES ($1, $2, 'automation_operator', $3, 'ORG', $4, now() - interval '30 days')`,
				[]any{g.org, ids.NewV7(), g.dave.id, "user:" + g.alice.id.String()},
			},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (g gateFx) gate(step string, exclude ...ids.UUID) approvals.AutomationGate {
	digest := sha256.Sum256([]byte(`{"ticket":"T-1"}`))
	return approvals.AutomationGate{
		Org: g.org, Automation: g.automation, AutomationName: "refunds", ServiceAccount: g.sa, Execution: g.execution,
		StepID: step, Attempt: 1, ParamsDigest: digest[:], Params: map[string]string{"ticket": "T-1"},
		Summary: "Refund ticket T-1", MinApprovals: 1, Deadline: time.Hour, Exclude: exclude,
	}
}

func (g gateFx) request(in approvals.AutomationGate) (ids.UUID, int) {
	g.t.Helper()
	var id ids.UUID
	var n int
	if err := g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, n, err = g.svc.RequestAutomationGateTx(ctx, tx.Pgx(), in)
		return err
	}); err != nil {
		g.t.Fatal(err)
	}
	return id, n
}

// TestHR281_AnAgentlessGateIsApprovedEndToEnd (D25, D25a, D62, D84 E2): a
// gate with no agent is requested by the automation, routed to its
// AUTOMATION_GATE entry, listed in the decider's inbox and the API list
// without breaking them, refused to a plain Approver and to the excluded
// owner, approved by an Automation Operator with a security key, and then
// consumed once by its step.
func TestHR281_AnAgentlessGateIsApprovedEndToEnd(t *testing.T) {
	g := newGateFx(t)
	id, n := g.request(g.gate("approve", g.alice.id))
	if id.IsZero() || n != 1 {
		t.Fatalf("gate %s with %d eligible, want one (dave)", id, n)
	}
	if s := g.str(`SELECT coalesce(agent_id::text, 'none') || ' ' || subject_kind || ' ' || requested_by_automation::text || ' ' || step_id
		FROM pc.approval_requests WHERE id = $1`, id); s != "none AUTOMATION_GATE "+g.automation.String()+" approve" {
		t.Fatalf("request %q", s)
	}
	if s := g.str(`SELECT kind || ' ' || state || ' ' || requested_by_automation::text FROM pc.waitlist_entries
		WHERE subject_id = $1`, id); s != "AUTOMATION_GATE OPEN "+g.automation.String() {
		t.Fatalf("entry %q", s)
	}
	again, _ := g.request(g.gate("approve", g.alice.id))
	if again != id {
		t.Fatalf("a second request for the step: %s", again)
	}

	// An ACTION hold beside it: one gate never breaks the lists (E2).
	hold := g.fx.request(1)
	// dave is also an Approver: he sees both; bob only the hold.
	in, err := g.svc.Inbox(g.as(g.dave))
	if err != nil || len(in.Waiting) != 2 || !slices.ContainsFunc(in.Waiting, func(s approvals.Summary) bool { return s.ID == id }) {
		t.Fatalf("dave's inbox %+v, %v", in.Waiting, err)
	}
	if in, err := g.svc.Inbox(g.as(g.bob)); err != nil || len(in.Waiting) != 1 || in.Waiting[0].ID != hold {
		t.Fatalf("bob's inbox %+v, %v", in.Waiting, err)
	}
	if l, err := g.svc.List(g.as(g.dave), page.Request{Size: 50}, approvals.ListFilter{WaitingForMe: true}); err != nil ||
		!slices.ContainsFunc(l.Items, func(r approvals.Request) bool { return r.ID == id }) {
		t.Fatalf("dave's list %v, %v", l.Items, err)
	}
	if v, err := g.svc.View(g.as(g.dave), id); err != nil || v.Display.Kind != "automation_gate" {
		t.Fatalf("view: %v", err)
	}

	for name, p := range map[string]person{"a plain approver": g.bob, "the excluded owner": g.alice, "no role": g.carol} {
		if _, err := g.svc.BeginApproval(context.Background(), g.org, approvals.Responder{User: p.id, Browser: p.browser}, id); !errors.Is(err, approvals.ErrNotEligible) && !errors.Is(err, approvals.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r, err := g.approve(g.dave, id)
	if err != nil || r.State != "APPROVED" || r.ConsumeBy == nil || !r.ConsumeBy.Equal(r.DeadlineAt) {
		t.Fatalf("dave's approval: %s %v, %v", r.State, r.ConsumeBy, err)
	}
	var st approvals.AutomationGateState
	if err := g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		if st, err = g.svc.AutomationGateStateTx(ctx, tx.Pgx(), g.org, id); err != nil {
			return err
		}
		if err := g.svc.ConsumeAutomationGateTx(ctx, tx.Pgx(), g.org, id); err != nil {
			return err
		}
		if err := g.svc.ConsumeAutomationGateTx(ctx, tx.Pgx(), g.org, id); !errors.Is(err, approvals.ErrNotWaiting) {
			t.Errorf("a second consumption: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if st.State != "APPROVED" || len(st.Approvers) != 1 || st.Approvers[0] != g.dave.id {
		t.Fatalf("state %+v", st)
	}
	if s := g.str("SELECT state FROM pc.approval_requests WHERE id = $1", id); s != "CONSUMED" {
		t.Fatalf("after consumption %s", s)
	}
}

// TestHR281_NoEligibleDeciderWritesNoGate (D25): a gate nobody may decide
// is not created; ending a live gate expires it and closes its entry.
func TestHR281_NoEligibleDeciderWritesNoGate(t *testing.T) {
	g := newGateFx(t)
	if id, n := g.request(g.gate("nobody", g.dave.id)); !id.IsZero() || n != 0 {
		t.Fatalf("gate %s with %d eligible", id, n)
	}
	if s := g.str("SELECT count(*)::text FROM pc.approval_requests WHERE subject_kind = 'AUTOMATION_GATE'"); s != "0" {
		t.Fatalf("%s gates written", s)
	}
	id, _ := g.request(g.gate("later"))
	if err := g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		return g.svc.EndAutomationGateTx(ctx, tx.Pgx(), g.org, id, "GATE_EXPIRED")
	}); err != nil {
		t.Fatal(err)
	}
	if s := g.str(`SELECT r.state || ' ' || e.state FROM pc.approval_requests r JOIN pc.waitlist_entries e
		ON e.subject_id = r.id WHERE r.id = $1`, id); s != "EXPIRED EXPIRED" {
		t.Fatalf("ended gate %q", s)
	}
}
