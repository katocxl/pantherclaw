// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestPolicyOnCompromise: marking a person compromised voids their pending
// M11.1 policy change requests, and those they confirmed, and leaves the
// rest alone (G0 M11 D43, D72 P1, D90 L2).
func TestPolicyOnCompromise(t *testing.T) {
	pool := dbtest.New(t).AppPool(t)
	org, mallory, alice := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	theirs, others, confirmed := ids.NewV7(), ids.NewV7(), ids.NewV7()
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
	}{{theirs, mallory}, {others, alice}, {confirmed, alice}} {
		exec(`INSERT INTO pc.policy_change_requests (org_id, id, kind, subject_id, binding, summary, required, requested_by)
			VALUES ($1, $2, 'PUBLISH', $3, decode(repeat('ab', 32), 'hex'), '{}', 1, $4)`,
			org, r.id, ids.NewV7(), td.PrincipalRef{Kind: td.KindUser, ID: r.by}.String())
	}
	// Mallory confirmed alice's third request with her key (D90 L2).
	key := ids.NewV7()
	exec(`INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'mallory')`, org, mallory)
	exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
		attestation_fmt, name) VALUES ($1, $2, $3, decode(repeat('ab', 16), 'hex'), decode(repeat('cd', 32), 'hex'), -7, false, false, 'none', 'k')`,
		org, key, mallory)
	exec(`INSERT INTO pc.policy_change_confirmations (org_id, request_id, principal_id, credential_id) VALUES ($1, $2, $3, $4)`,
		org, confirmed, mallory, key)
	by := tapp.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: alice}}}
	var details map[string]string
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		details, err = policyOnCompromise(ctx, tx, mallory, time.Now().Add(-time.Hour), by)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if details["policy_requests_voided"] != "2" || details["policy_rollouts_halted"] != "0" {
		t.Fatalf("details %v", details)
	}
	for id, want := range map[ids.UUID]string{theirs: "VOIDED", others: "PENDING", confirmed: "VOIDED"} {
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

// TestD110_MarkingVoidsTheCeilingsThePersonApproved (P3): marking a person
// compromised voids, in the marking transaction, every ACTIVE ceiling they
// approved (reason COMPROMISED_PUBLISHER), which pauses its automation and
// revokes what was issued under it; a ceiling someone else approved is
// left alone.
func TestD110_MarkingVoidsTheCeilingsThePersonApproved(t *testing.T) {
	d := dbtest.New(t)
	pool := d.AppPool(t)
	core, p := newM11Core(pool, nil, "https://pc.example.test")
	// As in a worker: cmdServe attaches the gated grants and runs services
	// before the role split (D113), then the core jobs register.
	attachM11Issuance(core, pool)
	if _, err := registerAutomationsCoreJobs(nil, jobs.NewRegistry(), core, nil); err != nil {
		t.Fatal(err)
	}
	org, mallory, alice := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
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
	for name, id := range map[string]ids.UUID{"mallory": mallory, "alice": alice} {
		exec(`INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)`, org, id, name)
	}
	// Two enabled automations, one under a ceiling mallory approved and one
	// under alice's.
	d.AdminExec(t, "ALTER TABLE pc.automations DISABLE TRIGGER USER")
	d.AdminExec(t, "ALTER TABLE pc.automation_versions DISABLE TRIGGER USER")
	d.AdminExec(t, "ALTER TABLE pc.automation_ceilings DISABLE TRIGGER USER")
	ceilings := map[ids.UUID]ids.UUID{}
	autos := map[ids.UUID]ids.UUID{}
	for i, approver := range []ids.UUID{mallory, alice} {
		a, v, req, c := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
		sa, name := ids.NewV7(), "auto-"+strconv.Itoa(i)
		if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO pc.automations (org_id, id, name, purpose, kind, owner_user_id,
				service_account_id, created_by) VALUES ($1, $2, $3, 'test', 'SECURITY_WORK', $4, $5, $4)`, org, a, name, alice, sa); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO pc.service_accounts (org_id, id, name, created_by, automation_id)
				VALUES ($1, $2, $3, 'test', $4)`, org, sa, name, a)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO pc.automation_versions (org_id, id, automation_id, number, state, definition, digest, created_by,
			validated_at, tested_at, published_at) VALUES ($1, $2, $3, 1, 'PUBLISHED', '{}', decode(repeat('ab', 32), 'hex'), $4,
			now(), now(), now())`, org, v, a, alice)
		exec(`UPDATE pc.automations SET state = 'ACTIVE', rollout = 'FULL', enabled_version_id = $3 WHERE org_id = $1 AND id = $2`,
			org, a, v)
		exec(`INSERT INTO pc.change_requests (org_id, id, domain, kind, subject_id, content_digest, binding, summary, required,
			requested_by, expires_at) VALUES ($1, $2, 'automation', 'ENABLE', $3, decode(repeat('ab', 32), 'hex'),
			decode(repeat('cd', 32), 'hex'), '{}', 1, 'user:x', now() + interval '1 hour')`, org, req, a)
		exec(`INSERT INTO pc.automation_ceilings (org_id, id, automation_id, version_id, digest, approved_by, change_request_id,
			review_by) VALUES ($1, $2, $3, $4, decode(repeat('ab', 32), 'hex'), ARRAY[$5::uuid], $6, now() + interval '30 days')`,
			org, c, a, v, approver, req)
		ceilings[approver], autos[approver] = c, a
	}
	d.AdminExec(t, "ALTER TABLE pc.automations ENABLE TRIGGER USER")
	d.AdminExec(t, "ALTER TABLE pc.automation_versions ENABLE TRIGGER USER")
	d.AdminExec(t, "ALTER TABLE pc.automation_ceilings ENABLE TRIGGER USER")

	by := tapp.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: alice}}}
	voided := ""
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for _, on := range p.publishers.On {
			details, err := on(ctx, tx, mallory, time.Now().Add(-time.Hour), by)
			if err != nil {
				return err
			}
			if v, ok := details["ceilings_voided"]; ok {
				voided = v
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if voided != "1" {
		t.Fatalf("ceilings voided %q, want 1", voided)
	}
	state := func(sql string, args ...any) (out string) {
		t.Helper()
		if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, sql, args...).Scan(&out)
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	ceiling := `SELECT state || ':' || coalesce(void_reason, '') FROM pc.automation_ceilings WHERE org_id = $1 AND id = $2`
	automation := `SELECT state FROM pc.automations WHERE org_id = $1 AND id = $2`
	if got := state(ceiling, org, ceilings[mallory]); got != "VOID:COMPROMISED_PUBLISHER" {
		t.Errorf("mallory's ceiling is %s", got)
	}
	if got := state(automation, org, autos[mallory]); got != "PAUSED" {
		t.Errorf("mallory's automation is %s", got)
	}
	if got := state(ceiling, org, ceilings[alice]); got != "ACTIVE:" {
		t.Errorf("alice's ceiling is %s", got)
	}
	if got := state(automation, org, autos[alice]); got != "ACTIVE" {
		t.Errorf("alice's automation is %s", got)
	}
}
