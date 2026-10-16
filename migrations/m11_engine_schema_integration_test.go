// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// m11EngineFixture extends the M5 part 2 fixture with an automation, its
// execution identity, a version and a SHADOW execution (00142).
type m11EngineFixture struct {
	m5p2Fixture
	automation, sa, version, execution, trigger string
}

const (
	m11Execution = `INSERT INTO pc.automation_executions (org_id, id, automation_id, version_id, trigger_id, mode,
		service_account_id, principal_sa_id, trigger_kind, occurred_at, root_trigger_id, deadline_at)
		VALUES ($1, $2, $3, $4, $5, 'SHADOW', $6, $6, 'MANUAL', now(), $5, now() + interval '1 day')`
	m11Attempt = `INSERT INTO pc.automation_step_attempts (org_id, id, execution_id, step_index, step_id, attempt, kind, state)
		VALUES ($1, $2, $3, 0, 'notify', 1, 'notify', $4)`
	m11Gate = `INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, requested_by, requested_by_automation,
		execution_id, step_id, operation, binding, binding_input, requirements, display, display_hash, deadline_at)
		VALUES ($1, $2, 'AUTOMATION_GATE', $3, $4, $5, $6, $7, 'automation.gate', $8, '\x7b7d',
		'[{"kind":"approval","role":"automation_operator","count":1}]', '{}', $8, date_trunc('second', now()) + interval '1 hour')`
	m11GateEntry = `INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, requested_by,
		requested_by_automation, deadline_at) VALUES ($1, $2, 'AUTOMATION_GATE', 'approval_request', $3, $4, $5, $6,
		now() + interval '1 hour')`
)

func newM11EngineFixture(t *testing.T, d *dbtest.DB) m11EngineFixture {
	t.Helper()
	f := m11EngineFixture{
		m5p2Fixture: newM5p2Fixture(t, newM5Fixture(t, d.AppPool(t))),
		automation:  m5ID(), sa: m5ID(), version: m5ID(), execution: m5ID(), trigger: m5ID(),
	}
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO pc.service_accounts (org_id, id, name, description, created_by, automation_id)
				VALUES ($1, $2, 'automation-refunds', '', 'test', $3)`, []any{f.org, f.sa, f.automation}},
			{`INSERT INTO pc.automations (org_id, id, name, purpose, kind, owner_user_id, service_account_id, created_by)
				VALUES ($1, $2, 'refunds', 'Refunds.', 'AGENT_WORK', $3, $4, $3)`, []any{f.org, f.automation, f.user, f.sa}},
			{`INSERT INTO pc.automation_versions (org_id, id, automation_id, number, definition, digest, created_by)
				VALUES ($1, $2, $3, 1, '{}', $4, $5)`, []any{f.org, f.version, f.automation, m5Secret(40), f.user}},
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
	f.mustExec(t, m11Execution, f.org, f.execution, f.automation, f.version, f.trigger, f.sa)
	return f
}

// TestM11Engine_PcAppUpdatesOnlyTransitions (00142): pc_app updates only
// the transition columns of executions, attempts and launches, deletes
// nothing, and RLS is forced.
func TestM11Engine_PcAppUpdatesOnlyTransitions(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	updatable := map[string][]string{
		"automation_executions": {
			"state", "reason", "current_step", "compensating", "result", "transitions", "started_at", "updated_at",
			"ended_at", "wake_at", "cancel_requested_by", "cancel_reason", "cancel_requested_at",
		},
		"automation_step_attempts": {"state", "decision", "reason", "output", "refs", "effect", "ended_at", "wake_at"},
		"automation_launches": {
			"state", "claimed_instance_id", "claimed_at", "completed_at", "outcome", "report", "delivery_id", "ended_at",
		},
	}
	for table, allowed := range updatable {
		rows, err := m.Pgx().Query(ctx, `SELECT column_name FROM information_schema.columns
			WHERE table_schema = 'pc' AND table_name = $1`, table)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		rows.Close()
		if len(cols) < 8 {
			t.Fatalf("%s has %d columns", table, len(cols))
		}
		for _, c := range cols {
			var got bool
			if err := m.Pgx().QueryRow(ctx, `SELECT has_column_privilege('pc_app', 'pc.' || $1, $2, 'UPDATE')`, table, c).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if want := slices.Contains(allowed, c); got != want {
				t.Errorf("pc_app UPDATE on pc.%s.%s = %v, want %v", table, c, got, want)
			}
		}
		var del, forced bool
		if err := m.Pgx().QueryRow(ctx, `SELECT has_table_privilege('pc_app', 'pc.' || $1, 'DELETE'),
			(SELECT relforcerowsecurity FROM pg_class WHERE oid = ('pc.' || $1)::regclass)`, table).Scan(&del, &forced); err != nil {
			t.Fatal(err)
		}
		if del || !forced {
			t.Errorf("pc.%s: pc_app DELETE %v, RLS forced %v", table, del, forced)
		}
	}
	var def string
	if err := m.Pgx().QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conname = 'evidence_packs_scope_kind_check'`).Scan(&def); err != nil || !strings.Contains(def, "automation_execution") {
		t.Errorf("evidence pack scope = %q (%v)", def, err)
	}
}

// TestHR280_FinishedExecutionsAndAttemptsNeverChange (00142): a terminal
// execution or step attempt is immutable; an execution's identity never
// changes; NEEDS_RECONCILIATION only resolves to a final state.
func TestHR280_FinishedExecutionsAndAttemptsNeverChange(t *testing.T) {
	d := dbtest.New(t)
	f := newM11EngineFixture(t, d)
	f.want(t, m5Unique, "a second execution of one trigger", m11Execution, f.org, m5ID(), f.automation, f.version, f.trigger, f.sa)
	f.want(t, m5Denied, "updating the version", "UPDATE pc.automation_executions SET version_id = version_id WHERE id = $1", f.execution)
	f.want(t, m5Denied, "updating the trigger", "UPDATE pc.automation_executions SET trigger_id = trigger_id WHERE id = $1", f.execution)

	done := m5ID()
	f.mustExec(t, m11Attempt, f.org, done, f.execution, "DONE")
	f.want(t, m5Check, "a finished attempt changes", "UPDATE pc.automation_step_attempts SET state = 'FAILED' WHERE id = $1", done)
	f.want(t, m5Unique, "a second first attempt", m11Attempt, f.org, m5ID(), f.execution, "DONE")
	waiting := m5ID()
	f.mustExec(t, strings.Replace(m11Attempt, "0, 'notify', 1", "1, 'wait', 1", 1), f.org, waiting, f.execution, "WAITING")
	f.mustExec(t, "UPDATE pc.automation_step_attempts SET state = 'DONE' WHERE id = $1", waiting)

	f.want(t, m5Check, "finished without a result",
		"UPDATE pc.automation_executions SET state = 'SUCCEEDED' WHERE id = $1", f.execution)
	f.mustExec(t, `UPDATE pc.automation_executions SET state = 'NEEDS_RECONCILIATION', reason = 'EFFECT_UNKNOWN',
		result = '{}' WHERE id = $1`, f.execution)
	f.want(t, m5Check, "reconciliation back to running",
		"UPDATE pc.automation_executions SET state = 'RUNNING', reason = NULL, result = NULL WHERE id = $1", f.execution)
	f.mustExec(t, `UPDATE pc.automation_executions SET state = 'PARTIALLY_COMPLETED', reason = 'FINISH_NOT_MET'
		WHERE id = $1`, f.execution)
	f.want(t, m5Check, "a finished execution changes",
		"UPDATE pc.automation_executions SET wake_at = now() WHERE id = $1", f.execution)
}

// TestHR281_GatesAreAutomationRequestsWithoutAnAgent (00142, D25a, D62):
// an AUTOMATION_GATE request names its execution, step and automation, may
// have no agent, and has one live request per step; other kinds keep their
// agent and person requester.
func TestHR281_GatesAreAutomationRequestsWithoutAnAgent(t *testing.T) {
	d := dbtest.New(t)
	f := newM11EngineFixture(t, d)
	none := (*string)(nil)
	gate := m5ID()
	f.mustExec(t, m11Gate, f.org, gate, nil, none, f.automation, f.execution, "approve", m5Secret(50))
	f.want(t, m5Unique, "two live gates for one step", m11Gate, f.org, m5ID(), nil, none, f.automation, f.execution,
		"approve", m5Secret(51))
	f.mustExec(t, m11Gate, f.org, m5ID(), f.agent, none, f.automation, f.execution, "second", m5Secret(52))
	f.want(t, m5Check, "a gate without its automation", m11Gate, f.org, m5ID(), nil, none, nil, f.execution,
		"third", m5Secret(53))
	f.want(t, m5Check, "a gate with a person requester", m11Gate, f.org, m5ID(), nil, &f.user, f.automation, f.execution,
		"fourth", m5Secret(54))
	f.want(t, m5Check, "a restoration without its agent", `INSERT INTO pc.approval_requests (org_id, id, subject_kind,
		requested_by, operation, binding, binding_input, requirements, display, display_hash, deadline_at)
		VALUES ($1, $2, 'RESTORATION', $3, 'agent.restore', $4, '\x7b7d', '[{"kind":"approval","role":"approver","count":1}]',
		'{}', $4, date_trunc('second', now()) + interval '24 hours')`, f.org, m5ID(), f.user, m5Secret(55))
	f.mustExec(t, `UPDATE pc.approval_requests SET state = 'APPROVED', approved_at = now(), consume_by = deadline_at
		WHERE id = $1`, gate)
	f.mustExec(t, `UPDATE pc.approval_requests SET state = 'CONSUMED', consumed_at = now(), ended_at = now()
		WHERE id = $1`, gate)

	f.mustExec(t, m11GateEntry, f.org, m5ID(), gate, nil, none, f.automation)
	f.want(t, m5Check, "a gate entry without its automation", m11GateEntry, f.org, m5ID(), m5ID(), nil, none, nil)
	by := "user:" + f.user
	f.want(t, m5Check, "a gate entry with a person requester", m11GateEntry, f.org, m5ID(), m5ID(), nil, &by, f.automation)
	f.want(t, m5Check, "a restoration entry naming an automation", `INSERT INTO pc.waitlist_entries (org_id, id, kind,
		subject_type, subject_id, agent_id, requested_by, requested_by_automation, deadline_at)
		VALUES ($1, $2, 'RESTORATION', 'approval_request', $3, $4, $5, $6, now() + interval '1 hour')`,
		f.org, m5ID(), m5ID(), f.agent, &by, f.automation)
}

// TestM11Engine_RunsOfAnExecutionAreLaunchedByItsAccount (00142, D64): a
// run naming an execution is launched by that execution's service account
// and never changes execution.
func TestM11Engine_RunsOfAnExecutionAreLaunchedByItsAccount(t *testing.T) {
	d := dbtest.New(t)
	f := newM11EngineFixture(t, d)
	env := m5ID()
	f.mustExec(t, "INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'auto', 'Auto', 'DEVELOPMENT')", f.org, env)
	other := m5ID()
	f.mustExec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'ci', 'test')", f.org, other)
	const run = `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_sa_id, principal_sa_id,
		principal_source, automation_execution_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'automation', $6, now() + interval '1 hour')`
	f.want(t, m5Check, "a run of an execution launched by another account", run, f.org, m5ID(), f.agent, env, other, f.execution)
	id := m5ID()
	f.mustExec(t, run, f.org, id, f.agent, env, f.sa, f.execution)
	f.want(t, m5Denied, "re-assigning a run's execution",
		"UPDATE pc.runs SET automation_execution_id = NULL WHERE id = $1", id)
}
