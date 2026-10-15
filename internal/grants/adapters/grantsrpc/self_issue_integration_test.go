// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package grantsrpc_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR243_AServiceAccountIssuingAGrantOverTheAPIIsDetected: a service
// account calling IssueGrant is refused by the RPC layer before any use
// case runs; the refusal is audited once per minute as
// rpc.human_only_refused, and pc.authority.self_issue raises an alert from
// it (G0 M10 D67, PN-006.3).
func TestHR243_AServiceAccountIssuingAGrantOverTheAPIIsDetected(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	o := seed(t, s)
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	e := &engine.Engine{Pool: s.pool, Builtin: p.Rules, PackVersion: p.Version, Env: env, Raiser: &alerts.Raiser{}, Sink: &failures.Sink{}}
	if _, err := e.Process(ctx, o.org); err != nil { // the cursor starts at the feed's head
		t.Fatal(err)
	}
	key := s.apiKey(t, o.org, []string{string(td.PermGrantRead)}, td.RoleViewer)
	grants, _ := s.clients(key)
	for range 3 {
		_, err := grants.IssueGrant(ctx, &pb.IssueGrantRequest{AgentId: o.agent.String()})
		wantCode(t, "a service account issuing a grant", err, connect.CodePermissionDenied)
	}
	count := func(sql string) int {
		var n int
		if err := s.pool.InTenantTx(ctx, o.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, sql, o.org).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.rpc.human_only_refused'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'procedure' = '/pantherclaw.v1.GrantService/IssueGrant'`); n != 1 {
		t.Fatalf("refusal entries %d, want 1 (deduplicated)", n)
	}
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(100 * time.Millisecond) {
		if _, err := ledger.ChainAll(ctx, s.pool, o.org, 100); err != nil {
			t.Fatal(err)
		}
		if count(`SELECT count(*) FROM pc.ledger_entries e WHERE org_id = $1
			AND NOT EXISTS (SELECT 1 FROM pc.ledger_chain c WHERE c.org_id = e.org_id AND c.entry_id = e.id)`) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not chained")
		}
	}
	if _, err := e.Process(ctx, o.org); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND rule_id = 'pc.authority.self_issue'`); n != 1 {
		t.Errorf("self_issue alerts %d, want 1", n)
	}
}
