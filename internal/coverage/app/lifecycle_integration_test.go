// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"strings"
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

// grant issues the agent an active grant allowing ops.
func (f *fixture) grant(t *testing.T, ops ...string) {
	t.Helper()
	f.grantBounds(t, []byte(`{"operations":["`+strings.Join(ops, `","`)+`"]}`))
}

// grantBounds grants the agent a grant with these bounds.
func (f *fixture) grantBounds(t *testing.T, bounds []byte) {
	t.Helper()
	grant := ids.NewV7()
	f.exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision,
		grantor_kind, grantor_id, basis) SELECT $1, $2, $3, $4, environment_id, 0, 1, 'user', $4, 'test'
		FROM pc.runs WHERE id = $5`, f.org, grant, f.agent, f.user, f.run)
	f.exec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements,
		limits, delegation_depth, max_children, min_attestation, widens, created_by) VALUES ($1, $2, $3, 1, now() - interval '1 hour',
		now() + interval '1 day', $4, '\x7b7d', '\x7b7d', 0, 0, 0, false, 'test')`,
		f.org, ids.NewV7(), grant, bounds)
}

func (f *fixture) exclude(t *testing.T, op string) {
	t.Helper()
	f.exec(t, `INSERT INTO pc.coverage_exclusions (org_id, id, agent_id, connection_id, operation, reason, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'Reads only; reviewed by the security team.', $6, now() + interval '30 days')`,
		f.org, ids.NewV7(), f.agent, f.conn, op, f.user)
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, agent_id) VALUES ($1, $2, 'exclusion', $3, $4)`,
		f.org, ids.NewV7(), f.conn, f.agent)
}

// TestF021_TheAgentFollowsTheCoverageOfWhatItsGrantsAllow: the scopes that
// count are the operations the agent's grants allow on every connection
// that defines them, and one never assessed counts as not ENFORCED. Without
// a grant the agent stays OBSERVED; granted only an ENFORCED scope it is
// PROTECTED once that scope is reassessed. A grant alone, which writes no
// coverage change, lowers a protected agent at the next job. With one
// scope ENFORCED, one capped at PARTIAL (a cooperative SDK route, HR-024)
// and one never assessed, the agent is PARTIALLY_PROTECTED, and stays so
// when a person excludes the other two: an excluded scope counts as not
// protected (HR-212, design decision 1). It is OBSERVED when a route mode
// change invalidates the closure (HR-211).
func TestF021_TheAgentFollowsTheCoverageOfWhatItsGrantsAllow(t *testing.T) {
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
	if s := f.agentState(t); s != "OBSERVED" {
		t.Fatalf("without a grant: %s", s)
	}
	f.grant(t, "payments.refund.create")
	f.reassess(t)
	if s := f.agentState(t); s != "PROTECTED" {
		t.Fatalf("granted only the enforced scope: %s", s)
	}
	f.grant(t, "payments.refund.list")
	f.reassessOrg(t)
	if s := f.agentState(t); s != "PARTIALLY_PROTECTED" {
		t.Fatalf("after a grant of a scope never assessed: %s", s)
	}
	f.grant(t, "payments.refund.create", "payments.refund.get", "payments.refund.list")
	f.exclude(t, "payments.refund.get")
	f.reassessOrg(t)
	if s := f.agentState(t); s != "PARTIALLY_PROTECTED" {
		t.Fatalf("with list never assessed: %s", s)
	}
	f.exclude(t, "payments.refund.list")
	f.reassessOrg(t)
	if s := f.agentState(t); s != "PARTIALLY_PROTECTED" {
		t.Fatalf("with the other scopes excluded: %s", s)
	}
	f.exec(t, `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
		VALUES ($1, $2, 'payments-refund', 'monitor', 'test')`, f.org, f.conn)
	f.reassessOrg(t)
	if s := f.agentState(t); s != "OBSERVED" {
		t.Fatalf("after a route mode change: %s", s)
	}
}
