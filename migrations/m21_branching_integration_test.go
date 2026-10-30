// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/migrations"
)

const (
	m21Up            = "00246_automation_node_state.sql"
	m21Guards        = "00247_automation_node_guards.sql"
	m21OldAttempt    = `INSERT INTO pc.automation_step_attempts (org_id, id, execution_id, step_index, step_id, attempt, kind, state) VALUES ($1, $2, $3, $4, $5, 1, 'notify', $6)`
	m21Permission    = "42501"
	m21SetWaiting    = `UPDATE pc.automation_executions SET state = 'WAITING', current_step = 1 WHERE org_id = $1 AND id = $2`
	m21TerminalNode  = `UPDATE pc.automation_step_attempts SET node_id = 'other' WHERE step_id = 'first'`
	m21NoForce       = `ALTER TABLE pc.automation_step_attempts NO FORCE ROW LEVEL SECURITY`
	m21Force         = `ALTER TABLE pc.automation_step_attempts FORCE ROW LEVEL SECURITY`
	m21AttemptRow    = `SELECT node_id, visit FROM pc.automation_step_attempts WHERE org_id = $1 AND id = $2`
	m21ExecutionRow  = `SELECT state, current_step, current_node, cardinality(path) FROM pc.automation_executions WHERE org_id = $1 AND id = $2`
	m21Pointer       = `UPDATE pc.automation_executions SET current_node = $3, path = $4 WHERE org_id = $1 AND id = $2`
	m21VersionChange = `UPDATE pc.automation_executions SET version_id = $3 WHERE org_id = $1 AND id = $2`
)

func m21Sections(t *testing.T, name string) (up, down string) {
	t.Helper()
	b, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatalf("%s has no Down section", name)
	}
	return up, down
}

// m21Back steps 00247 and 00246 down, as a database before M21 is; the
// returned func applies them again, as the upgrade does.
func m21Back(t *testing.T, d *dbtest.DB) (migrate func()) {
	t.Helper()
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	exec := func(what, sql string) {
		t.Helper()
		if _, err := m.Pgx().Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	up246, down246 := m21Sections(t, m21Up)
	up247, down247 := m21Sections(t, m21Guards)
	exec("00247 down", down247)
	exec("00246 down", down246)
	return func() {
		t.Helper()
		exec("00246 up", up246)
		exec("00247 up", up247)
	}
}

// TestHR530_WaitingV1ExecutionsMigrate: a database holding a WAITING v1
// execution with a finished and a waiting attempt upgrades; every attempt
// gets its node, the pointer stays on the step index, and the waiting attempt
// goes on (D301, D307).
//
// Covers: F678
func TestHR530_WaitingV1ExecutionsMigrate(t *testing.T) {
	d := dbtest.New(t)
	f := newM11EngineFixture(t, d)
	done, waiting := m5ID(), m5ID()
	migrate := m21Back(t, d)

	f.mustExec(t, m21OldAttempt, f.org, done, f.execution, 0, "first", "DONE")
	f.mustExec(t, m21OldAttempt, f.org, waiting, f.execution, 1, "second", "WAITING")
	f.mustExec(t, m21SetWaiting, f.org, f.execution)

	migrate()

	ctx := context.Background()
	err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		for id, want := range map[string]string{done: "first", waiting: "second"} {
			var node string
			var visit int
			if err := tx.QueryRow(ctx, m21AttemptRow, f.org, id).Scan(&node, &visit); err != nil {
				return err
			}
			if node != want || visit != 1 {
				t.Errorf("attempt %s: node %q visit %d", want, node, visit)
			}
		}
		var state string
		var step, path int
		var current *string
		if err := tx.QueryRow(ctx, m21ExecutionRow, f.org, f.execution).Scan(&state, &step, &current, &path); err != nil {
			return err
		}
		if state != "WAITING" || step != 1 || current != nil || path != 0 {
			t.Errorf("execution %s step %d node %v path %d", state, step, current, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mustExec(t, `UPDATE pc.automation_step_attempts SET state = 'DONE' WHERE org_id = $1 AND id = $2`, f.org, waiting)
	f.mustExec(t, `UPDATE pc.automation_executions SET current_step = 2, state = 'RUNNING' WHERE org_id = $1 AND id = $2`, f.org, f.execution)
}

// TestHR533_NodeBackfillExceptionIsGone: after 00247 no node_id change gets
// through, on a finished attempt or a waiting one, whoever asks.
//
// Covers: F678
func TestHR533_NodeBackfillExceptionIsGone(t *testing.T) {
	d := dbtest.New(t)
	f := newM11EngineFixture(t, d)
	waiting := m5ID()
	f.mustExec(t, m21OldAttempt, f.org, m5ID(), f.execution, 0, "first", "DONE")
	f.mustExec(t, m21OldAttempt, f.org, waiting, f.execution, 1, "second", "WAITING")

	f.want(t, m21Permission, "pc_app cannot name another node", `UPDATE pc.automation_step_attempts SET node_id = 'other' WHERE org_id = $1 AND id = $2`, f.org, waiting)

	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	if _, err := m.Pgx().Exec(ctx, m21NoForce); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := m.Pgx().Exec(ctx, m21Force); err != nil {
			t.Error(err)
		}
	}()
	for what, sql := range map[string]string{
		"a finished attempt":      m21TerminalNode,
		"a waiting attempt":       `UPDATE pc.automation_step_attempts SET node_id = 'other' WHERE step_id = 'second'`,
		"a waiting attempt visit": `UPDATE pc.automation_step_attempts SET visit = 2 WHERE step_id = 'second'`,
	} {
		_, err := m.Pgx().Exec(ctx, sql)
		if err == nil || !strings.Contains(err.Error(), "never changes") {
			t.Errorf("%s: err = %v", what, err)
		}
	}
}

// TestHR533_PinnedVersionAndPointerNeverMove: a running execution keeps its
// version, its path only grows, and its current node is the last one
// entered.
//
// Covers: F678
func TestHR533_PinnedVersionAndPointerNeverMove(t *testing.T) {
	d := dbtest.New(t)
	f := newM11EngineFixture(t, d)
	f.mustExec(t, m21Pointer, f.org, f.execution, "route", []string{"route"})
	f.mustExec(t, m21Pointer, f.org, f.execution, "gate", []string{"route", "gate"})

	f.want(t, m5Check, "the pointer jumps with no entry", m21Pointer, f.org, f.execution, "other", []string{"route", "gate"})
	f.want(t, m5Check, "the path is rewritten", m21Pointer, f.org, f.execution, "other", []string{"route", "other"})
	f.want(t, m5Check, "the path shrinks", m21Pointer, f.org, f.execution, "route", []string{"route"})
	f.want(t, m5Check, "the path is cleared", m21Pointer, f.org, f.execution, nil, []string{})
	f.want(t, m21Permission, "the version moves", m21VersionChange, f.org, f.execution, f.version)
}
