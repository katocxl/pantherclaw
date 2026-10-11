// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func (f *fixture) agentState(t *testing.T) string {
	t.Helper()
	var s string
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state FROM pc.agents WHERE id = $1", f.agent).Scan(&s)
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestF021_TheAgentFollowsItsCoverage: an observed agent with one ENFORCED
// scope and one capped at PARTIAL (a cooperative SDK route, HR-024) is
// PARTIALLY_PROTECTED; it becomes PROTECTED when a person excludes the
// capped scope (HR-212: an exclusion weakens the claim, so only a person
// makes one), and OBSERVED when a route mode change invalidates the
// closure under both scopes (HR-211).
func TestF021_TheAgentFollowsItsCoverage(t *testing.T) {
	f := newFixture(t)
	team := ids.NewV7()
	f.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'coders', 'Coders')", f.org, team)
	f.exec(t, `UPDATE pc.agents SET state = 'OBSERVED', claimed_at = now(), team_id = $2, owner_user_id = $3, execution_context = 'ci',
		environment_id = (SELECT environment_id FROM pc.runs WHERE id = $4) WHERE id = $1`, f.agent, team, f.user, f.run)
	for op, channel := range map[string]string{"payments.refund.create": "http", "payments.refund.get": "sdk"} {
		f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7,
			$8, 'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), op, f.conn, channel)
	}
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	f.reassessOrg(t)
	if s := f.agentState(t); s != "PARTIALLY_PROTECTED" {
		t.Fatalf("with one scope enforced and one cooperative: %s", s)
	}
	f.exec(t, `INSERT INTO pc.coverage_exclusions (org_id, id, agent_id, connection_id, operation, reason, created_by, expires_at)
		VALUES ($1, $2, $3, $4, 'payments.refund.get', 'Reads only; reviewed by the security team.', $5, now() + interval '30 days')`,
		f.org, ids.NewV7(), f.agent, f.conn, f.user)
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, agent_id) VALUES ($1, $2, 'exclusion', $3, $4)`,
		f.org, ids.NewV7(), f.conn, f.agent)
	f.reassessOrg(t)
	if s := f.agentState(t); s != "PROTECTED" {
		t.Fatalf("with the cooperative scope excluded: %s", s)
	}
	f.exec(t, `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
		VALUES ($1, $2, 'payments-refund', 'monitor', 'test')`, f.org, f.conn)
	f.reassessOrg(t)
	if s := f.agentState(t); s != "OBSERVED" {
		t.Fatalf("after a route mode change: %s", s)
	}
}
