// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgengine_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/migrations"
)

const branchNodes = `"nodes":[
	{"id":"route","branch":{"when":"trigger.params.ticket == \"T-1\"","then":"launch","else":"approve"}},
	{"id":"launch","step":"launch_run","with":{"agent":"AGENT"},"next":"wait"},
	{"id":"wait","step":"wait_run","with":{"step":"launch"},"timeout":"2h","next":"ended"},
	{"id":"approve","step":"gate","with":{"approvers":{"roles":["automation_operator"]},"deadline":"1h"},"next":"nothing"},
	{"id":"ended","outcome":"SUCCEEDED","finish_when":[{"step":"wait","condition":"RUN_ENDED"}]},
	{"id":"nothing","outcome":"FAILED","finish_when":[{"step":"wait","condition":"RUN_ENDED"}]}]`

func (f *efx) pointer(exec ids.UUID) (node string, path []string) {
	f.t.Helper()
	f.Tx(f.t, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(current_node, ''), path FROM pc.automation_executions WHERE org_id = $1 AND id = $2`,
			f.Org, exec).Scan(&node, &path)
	})
	return node, path
}

// TestT231_APointerSurvivesEveryRound: a live v2 execution stores its node
// and path each round, resumes from them, and names its attempts by node.
//
// Covers: F678
func TestT231_APointerSurvivesEveryRound(t *testing.T) {
	f := newEfx(t, branchNodes)
	exec := f.start("T-1")
	f.advance(exec)
	node, path := f.pointer(exec)
	if node != "launch" && node != "wait" {
		t.Fatalf("node %q path %v", node, path)
	}
	if len(path) < 2 || path[0] != "route" || path[1] != "launch" {
		t.Fatalf("path %v", path)
	}
	f.advance(exec)
	next, again := f.pointer(exec)
	if len(again) < len(path) || next == "" {
		t.Fatalf("resumed at %q path %v, was %v", next, again, path)
	}
	if n := f.str(`SELECT count(*)::text FROM pc.automation_step_attempts WHERE org_id = $1 AND execution_id = $2 AND step_id = 'approve'`, f.Org, exec); n != "0" {
		t.Errorf("the other branch ran: %s attempts", n)
	}
	if n := f.str(`SELECT count(*)::text FROM pc.automation_step_attempts WHERE org_id = $1 AND execution_id = $2 AND node_id <> step_id`, f.Org, exec); n != "0" {
		t.Errorf("%s attempts name another node", n)
	}
}

// TestHR530_AWaitingV1ExecutionResumesAfterTheUpgrade: a v1 execution waiting
// before 00246 and 00247 is worked by the engine after them, on its index,
// with its waiting attempt named by the backfill.
//
// Covers: F678
func TestHR530_AWaitingV1ExecutionResumesAfterTheUpgrade(t *testing.T) {
	f := newEfx(t, launchSteps)
	exec := f.start("T-1")
	f.advance(exec)
	state := func() string {
		return f.str(`SELECT state || ' ' || current_step FROM pc.automation_executions WHERE org_id = $1 AND id = $2`, f.Org, exec)
	}
	before := state()
	if !strings.HasPrefix(before, "WAITING") {
		t.Fatalf("before the upgrade: %s", before)
	}

	up := map[string]string{}
	ctx := context.Background()
	m := f.DB.Pool(t, f.DB.Migrator)
	for _, name := range []string{"00247_automation_node_guards.sql", "00246_automation_node_state.sql"} {
		b, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		u, down, ok := strings.Cut(string(b), "-- +goose Down")
		if !ok {
			t.Fatalf("%s has no Down section", name)
		}
		up[name] = u
		if _, err := m.Pgx().Exec(ctx, down); err != nil {
			t.Fatalf("%s down: %v", name, err)
		}
	}
	for _, name := range []string{"00246_automation_node_state.sql", "00247_automation_node_guards.sql"} {
		if _, err := m.Pgx().Exec(ctx, up[name]); err != nil {
			t.Fatalf("%s up: %v", name, err)
		}
	}

	if n := f.str(`SELECT count(*)::text FROM pc.automation_step_attempts WHERE org_id = $1 AND execution_id = $2 AND node_id IS DISTINCT FROM step_id`, f.Org, exec); n != "0" {
		t.Fatalf("%s attempts without their node", n)
	}
	f.Pool.Pgx().Reset()
	inst := ids.NewV7()
	f.Exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, f.Org, inst, f.agent, inst.String()[:36]+"0000000")
	f.Exec(t, `UPDATE pc.automation_launches SET state = 'CLAIMED', claimed_instance_id = $3 WHERE org_id = $1 AND execution_id = $2`, f.Org, exec, inst)
	f.advance(exec)
	f.Exec(t, `UPDATE pc.runs SET state = 'ENDED', end_reason = 'completed', ended_at = now() WHERE org_id = $1`, f.Org)
	for range 3 {
		if s := state(); strings.HasPrefix(s, "WAITING") || strings.HasPrefix(s, "RUNNING") {
			f.advance(exec)
		}
	}
	if s := state(); !strings.HasPrefix(s, "SUCCEEDED") {
		t.Fatalf("the run ended and the execution is %s, was %s", s, before)
	}
	if node, path := f.pointer(exec); node != "" || len(path) != 0 {
		t.Fatalf("node %q path %v", node, path)
	}
}

// TestHR530_V1ExecutionsStayOnTheIndex: a v1 execution stores no node and no
// path, and its attempts name their step.
//
// Covers: F678
func TestHR530_V1ExecutionsStayOnTheIndex(t *testing.T) {
	f := newEfx(t, launchSteps)
	exec := f.start("T-1")
	f.advance(exec)
	if node, path := f.pointer(exec); node != "" || len(path) != 0 {
		t.Fatalf("node %q path %v", node, path)
	}
	if n := f.str(`SELECT count(*)::text FROM pc.automation_step_attempts WHERE org_id = $1 AND execution_id = $2 AND node_id = step_id`, f.Org, exec); n == "0" {
		t.Error("no attempt names its step as node")
	}
}
