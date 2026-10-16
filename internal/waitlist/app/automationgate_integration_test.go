// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

// gate opens an agentless AUTOMATION_GATE request needing one
// automation.approve holder, excluding owner, with its entry.
func (f *rfx) gate(owner ids.UUID) (entry, request ids.UUID) {
	f.t.Helper()
	automation, sa, version, trigger, execution := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	request = ids.NewV7()
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO pc.service_accounts (org_id, id, name, description, created_by, automation_id)
				VALUES ($1, $2, 'automation-refunds', '', 'test', $3)`, []any{f.org, sa, automation}},
			{`INSERT INTO pc.automations (org_id, id, name, purpose, kind, owner_user_id, service_account_id, created_by)
				VALUES ($1, $2, 'refunds', 'Refunds.', 'AGENT_WORK', $3, $4, $3)`, []any{f.org, automation, owner, sa}},
			{`INSERT INTO pc.automation_versions (org_id, id, automation_id, number, definition, digest, created_by)
				VALUES ($1, $2, $3, 1, '{}', $4, $5)`, []any{f.org, version, automation, make([]byte, 32), owner}},
			{`INSERT INTO pc.automation_triggers (org_id, id, automation_id, version_id, kind, mode, source_ref, authenticity,
				root_trigger_id, state, occurred_at) VALUES ($1, $2, $3, $4, 'MANUAL', 'SHADOW', 'manual:test', 'USER_SESSION',
				$2, 'SHADOW', now())`, []any{f.org, trigger, automation, version}},
			{
				`INSERT INTO pc.automation_executions (org_id, id, automation_id, version_id, trigger_id, mode, service_account_id,
				principal_sa_id, trigger_kind, occurred_at, root_trigger_id, deadline_at)
				VALUES ($1, $2, $3, $4, $5, 'SHADOW', $6, $6, 'MANUAL', now(), $5, now() + interval '1 day')`,
				[]any{f.org, execution, automation, version, trigger, sa},
			},
			{
				`INSERT INTO pc.approval_requests (org_id, id, subject_kind, requested_by_automation, execution_id, step_id, operation,
				binding, binding_input, requirements, display, display_hash, deadline_at)
				VALUES ($1, $2, 'AUTOMATION_GATE', $3, $4, 'approve', 'automation.gate', $5, '\x7b7d',
				jsonb_build_array(jsonb_build_object('kind', 'gate', 'count', 1, 'sources', '[]'::jsonb,
					'exclude', jsonb_build_array($6::text))), '{}', $5, date_trunc('second', now()) + interval '1 hour')`,
				[]any{f.org, request, automation, execution, append(append([]byte{}, request[:]...), request[:]...), owner.String()},
			},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		var err error
		entry, err = pgwaitlist.OpenAutomationGate(ctx, tx, f.org, request, automation, "approve",
			time.Now().Add(time.Hour).Truncate(time.Second), pgwaitlist.System)
		return err
	})
	return entry, request
}

// TestHR281_GateEntriesReachAutomationApprovers (D25a, D84 E2): an
// agentless gate entry is routed to the people holding automation.approve
// at the org, never to the excluded owner or a plain Approver, with the gate
// notice linking to the approval page; its escalation keeps the gate
// notices.
func TestHR281_GateEntriesReachAutomationApprovers(t *testing.T) {
	f := newRFx(t)
	owner := f.person("automation_operator", "ORG")
	operator := f.person("automation_operator", "ORG")
	f.person("approver", "ORG")
	f.person("automation_operator", "TEAM")
	entry, request := f.gate(owner)
	f.route()
	if got := f.routes(entry); !slices.Equal(got, []string{"decider:" + operator.String()}) {
		t.Fatalf("routes %v", got)
	}
	if got := f.sentTo(operator); !slices.Equal(got, []string{"automation.gate_requested"}) || f.n.link[0] != "/approvals/"+request.String() {
		t.Fatalf("notices %v %v", got, f.n.link)
	}
	if f.n.sent[0].Params["automation"] != "refunds" || f.n.sent[0].Params["step"] != "approve" {
		t.Fatalf("params %v", f.n.sent[0].Params)
	}
	f.due(entry)
	f.route()
	for _, typ := range f.sentTo(operator)[1:] {
		if typ != "automation.gate_reminder" && typ != "automation.gate_escalated" {
			t.Fatalf("escalation notice %s", typ)
		}
	}
}
