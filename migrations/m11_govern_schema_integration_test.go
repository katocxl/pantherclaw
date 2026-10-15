// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// govFixture is an org with a production environment, an agent, a person
// and their security key (00145).
type govFixture struct {
	org                    ids.OrgID
	env, agent, user, cred ids.UUID
}

func govOrg(t *testing.T, p *db.Pool) govFixture {
	t.Helper()
	f := govFixture{org: m10Org(t, p), env: ids.NewV7(), agent: ids.NewV7(), user: ids.NewV7(), cred: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, f.cred[:])
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'prod', 'Prod', 'PRODUCTION')", []any{f.org, f.env}},
		{"INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'a', 'DISCOVERED', 'system')", []any{f.org, f.agent}},
		{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", []any{f.org, f.user}},
		{`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
			attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`, []any{f.org, f.cred, f.user, secret[:16], secret}},
	} {
		if err := m10Exec(p, f.org, s.sql, s.args...); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f govFixture) promote(p *db.Pool, id ids.UUID, op, state string) error {
	return m10Exec(p, f.org, `INSERT INTO pc.agent_promotions (org_id, id, agent_id, environment_id, operation, state, checks,
		failure_behavior, promoted_by, credential_id) VALUES ($1, $2, $3, $4, $5, $6, '[]', 'FAIL_CLOSED', $7, $8)`,
		f.org, id, f.agent, f.env, op, state, f.user, f.cred)
}

// TestM11Govern_PromotionsChangeOnlyByOneRevocation (D39, HR-290): a
// promotion starts ACTIVE, one per agent, environment and operation; it is
// revoked once, with who and why, and nothing else about it changes.
func TestM11Govern_PromotionsChangeOnlyByOneRevocation(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	f := govOrg(t, p)
	id := ids.NewV7()
	if err := f.promote(p, ids.NewV7(), "payments.refund.create", "REVOKED"); err == nil {
		t.Fatal("a promotion started REVOKED")
	}
	if err := f.promote(p, id, "payments.refund.create", "ACTIVE"); err != nil {
		t.Fatal(err)
	}
	if err := f.promote(p, ids.NewV7(), "payments.refund.create", "ACTIVE"); err == nil {
		t.Fatal("two ACTIVE promotions of one operation")
	}
	for _, bad := range []string{"Payments.refund", "*", "payments.*.create", ""} {
		if err := f.promote(p, ids.NewV7(), bad, "ACTIVE"); err == nil {
			t.Errorf("operation %q accepted", bad)
		}
	}
	if err := m10Exec(p, f.org, "UPDATE pc.agent_promotions SET checks = '[{}]' WHERE id = $1", id); err == nil {
		t.Fatal("pc_app changed a promotion's checks")
	}
	if err := m10Exec(p, f.org, "UPDATE pc.agent_promotions SET state = 'REVOKED' WHERE id = $1", id); err == nil {
		t.Fatal("revoked without who and why")
	}
	revoke := "UPDATE pc.agent_promotions SET state = 'REVOKED', revoked_by = $2, revoked_at = now(), revoke_reason = 'done' WHERE id = $1"
	if err := m10Exec(p, f.org, revoke, id, f.user); err != nil {
		t.Fatal(err)
	}
	if err := m10Exec(p, f.org, revoke, id, f.user); err == nil {
		t.Fatal("revoked twice")
	}
	if err := m10Exec(p, f.org, "UPDATE pc.agent_promotions SET state = 'ACTIVE', revoked_by = NULL, revoked_at = NULL, revoke_reason = NULL WHERE id = $1", id); err == nil {
		t.Fatal("a revoked promotion came back")
	}
	if err := f.promote(p, ids.NewV7(), "payments.refund.create", "ACTIVE"); err != nil {
		t.Fatalf("promoting again after a revocation: %v", err)
	}
	if err := m10Exec(p, f.org, "DELETE FROM pc.agent_promotions WHERE id = $1", id); err == nil {
		t.Fatal("pc_app deleted a promotion")
	}
}

// TestTenancy_agent_promotions: another org neither reads nor changes an
// org's promotions, and cannot write into it.
func TestTenancy_agent_promotions(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := govOrg(t, p), govOrg(t, p)
	if err := a.promote(p, ids.NewV7(), "payments.*", "ACTIVE"); err != nil {
		t.Fatal(err)
	}
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.agent_promotions"); n != 0 {
		t.Fatalf("another org sees %d promotions", n)
	}
	if err := m10Exec(p, b.org, "UPDATE pc.agent_promotions SET state = 'REVOKED', revoked_by = $1, revoke_reason = 'x'", b.user); err != nil {
		t.Fatal(err)
	}
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.agent_promotions WHERE state = 'ACTIVE'"); n != 1 {
		t.Fatalf("another org revoked ours: %d active", n)
	}
	cross := govFixture{org: b.org, env: a.env, agent: a.agent, user: a.user, cred: a.cred}
	if err := cross.promote(p, ids.NewV7(), "payments.*", "ACTIVE"); err == nil {
		t.Fatal("promoted another org's agent")
	}
}

// TestTenancy_fleet_cohorts: cohorts and their members stay in their org;
// a cohort holds at most 1 000 static members.
func TestTenancy_fleet_cohorts(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := govOrg(t, p), govOrg(t, p)
	cohort := ids.NewV7()
	if err := m10Exec(p, a.org, `INSERT INTO pc.fleet_cohorts (org_id, id, name, owner_user_id, rule, created_by)
		VALUES ($1, $2, 'payments', $3, '{"task_type":"refunds"}', 'user:x')`, a.org, cohort, a.user); err != nil {
		t.Fatal(err)
	}
	if err := m10Exec(p, a.org, "INSERT INTO pc.fleet_cohort_members (org_id, cohort_id, agent_id, added_by) VALUES ($1, $2, $3, 'user:x')",
		a.org, cohort, a.agent); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"SELECT count(*) FROM pc.fleet_cohorts", "SELECT count(*) FROM pc.fleet_cohort_members"} {
		if n := m10Count(t, p, b.org, q); n != 0 {
			t.Fatalf("%s: another org sees %d", q, n)
		}
	}
	if err := m10Exec(p, b.org, "DELETE FROM pc.fleet_cohort_members"); err != nil {
		t.Fatal(err)
	}
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.fleet_cohort_members"); n != 1 {
		t.Fatalf("another org removed our member: %d", n)
	}
	if err := m10Exec(p, b.org, "INSERT INTO pc.fleet_cohort_members (org_id, cohort_id, agent_id, added_by) VALUES ($1, $2, $3, 'user:x')",
		b.org, cohort, b.agent); err == nil {
		t.Fatal("added a member to another org's cohort")
	}
	if err := m10Exec(p, a.org, `INSERT INTO pc.agents (org_id, id, name, state, created_by)
		SELECT $1, gen_random_uuid(), 'bulk', 'DISCOVERED', 'system' FROM generate_series(1, 1000)`, a.org); err != nil {
		t.Fatal(err)
	}
	err := m10Exec(p, a.org, `INSERT INTO pc.fleet_cohort_members (org_id, cohort_id, agent_id, added_by)
		SELECT $1, $2, id, 'user:x' FROM pc.agents WHERE name = 'bulk'`, a.org, cohort)
	if !db.IsCheckViolation(err) {
		t.Fatalf("a 1001st member: %v", err)
	}
	if err := m10Exec(p, a.org, "UPDATE pc.agents SET task_type = 'Refunds' WHERE id = $1", a.agent); err == nil {
		t.Fatal("a task type that is not a slug")
	}
}
