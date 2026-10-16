// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestPolicyOnCompromise: marking a person compromised voids their pending
// M11.1 policy change requests and leaves other people's alone (G0 M11 D43,
// D72 P1).
func TestPolicyOnCompromise(t *testing.T) {
	pool := dbtest.New(t).AppPool(t)
	org, mallory, alice := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	theirs, others := ids.NewV7(), ids.NewV7()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'protect')", org)
	for _, r := range []struct {
		id ids.UUID
		by ids.UUID
	}{{theirs, mallory}, {others, alice}} {
		exec(`INSERT INTO pc.policy_change_requests (org_id, id, kind, subject_id, binding, summary, required, requested_by)
			VALUES ($1, $2, 'PUBLISH', $3, decode(repeat('ab', 32), 'hex'), '{}', 1, $4)`,
			org, r.id, ids.NewV7(), td.PrincipalRef{Kind: td.KindUser, ID: r.by}.String())
	}
	by := tapp.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: alice}}}
	var details map[string]string
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		details, err = policyOnCompromise(ctx, tx, mallory, time.Now().Add(-time.Hour), by)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if details["policy_requests_voided"] != "1" || details["policy_rollouts_halted"] != "0" {
		t.Fatalf("details %v", details)
	}
	for id, want := range map[ids.UUID]string{theirs: "VOIDED", others: "PENDING"} {
		var state string
		if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT state FROM pc.policy_change_requests WHERE org_id = $1 AND id = $2", org, id).Scan(&state)
		}); err != nil {
			t.Fatal(err)
		}
		if state != want {
			t.Errorf("request %s is %s, want %s", id, state, want)
		}
	}
}
