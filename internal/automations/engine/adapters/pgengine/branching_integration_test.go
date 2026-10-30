// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgengine_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
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
